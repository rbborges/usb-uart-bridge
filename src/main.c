/*
 * Copyright (c) 2016 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/ring_buffer.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(usb_uart_bridge_main, LOG_LEVEL_INF);

#define USB_CONSOLE_DEV DEVICE_DT_GET(DT_CHOSEN(zephyr_console))
#define UART_DEV        DEVICE_DT_GET(DT_ALIAS(uart_device))

/* ~20 ms of buffering per direction at 1 Mbaud. */
#define PIPE_RING_SIZE 2048
/* Bytes moved per FIFO interaction; matches the CDC ACM bulk endpoint size. */
#define PIPE_CHUNK     64
/* Free space that must reappear before a throttled source is resumed. */
#define PIPE_RESUME    256

/*
 * usart1 talks to a peer running at a fixed rate, so the devicetree
 * current-speed is authoritative and host SET_LINE_CODING requests are only
 * reported, never applied. This matters because the CDC ACM class resets its
 * line coding to 115200 on every USB reset -- following it would silently drag
 * usart1 off 1 Mbaud the moment the port is enumerated.
 *
 * Set to 1 to let the host retune the UART instead.
 */
#define BRIDGE_FOLLOW_HOST_LINE_CODING 0

RING_BUF_DECLARE(usb_to_uart_rb, PIPE_RING_SIZE);
RING_BUF_DECLARE(uart_to_usb_rb, PIPE_RING_SIZE);

/*
 * A single direction of the bridge. Bytes read from src are buffered in rb and
 * drained to dst from dst's TX interrupt, so a stalled destination applies
 * backpressure to the source instead of costing bytes.
 */
struct pipe {
    const char *name;

    const struct device *src;
    const struct device *dst;

    struct ring_buf *rb;

    /* Set for pipes whose source is a real UART with error flags to poll. */
    bool monitor_errors;

    /* Counters, incremented from the ISR and reported from main(). */
    uint32_t dropped;      /* ring was full: lost between the two ports */
    uint32_t overruns;     /* ORE: lost at the pin, RX not serviced in time */
    uint32_t frame_errors; /* FE: usually a baud rate mismatch */
    uint32_t line_errors;  /* parity and noise */

    uint32_t reported_dropped;
    uint32_t reported_overruns;
    uint32_t reported_frame_errors;
    uint32_t reported_line_errors;
};

/* One port of the bridge, as seen by that device's ISR. */
struct port {
    struct pipe *in;  /* this device is the source */
    struct pipe *out; /* this device is the destination */
};

static struct pipe usb_to_uart = {
    .name = "usb->uart",
    .src  = USB_CONSOLE_DEV,
    .dst  = UART_DEV,
    .rb   = &usb_to_uart_rb,
};

static struct pipe uart_to_usb = {
    .name = "uart->usb",
    .src  = UART_DEV,
    .dst  = USB_CONSOLE_DEV,
    .rb   = &uart_to_usb_rb,

    .monitor_errors = true,
};

static struct port usb_port = { .in = &usb_to_uart, .out = &uart_to_usb };
static struct port uart_port = { .in = &uart_to_usb, .out = &usb_to_uart };

int usb_console_init(){
    uint32_t dtr = 0;

    int ret = usb_enable(NULL);
    if (ret) {
        return ret;
    }

    /* Poll if the DTR flag was set */
    while (!dtr) {
        uart_line_ctrl_get(USB_CONSOLE_DEV, UART_LINE_CTRL_DTR, &dtr);
        /* Give CPU resources to low priority threads. */
        k_sleep(K_MSEC(100));
    }
    
    return 0;
}

static const uint8_t data_bits_n[]     = {5, 6, 7, 8, 9};
static const char *const parity_s[]    = {"none", "odd", "even", "mark", "space"};
static const char *const stop_bits_s[] = {"0.5", "1", "1.5", "2"};

static bool uart_config_eq(const struct uart_config *a, const struct uart_config *b)
{
    return a->baudrate  == b->baudrate  &&
           a->parity    == b->parity    &&
           a->stop_bits == b->stop_bits &&
           a->data_bits == b->data_bits &&
           a->flow_ctrl == b->flow_ctrl;
}

/*
 * Reconcile the line coding the USB host asked for with the physical UART. The
 * legacy USB device stack does not report SET_LINE_CODING to the application,
 * so the CDC ACM device has to be polled for it.
 */
static void uart_config_sync(struct uart_config *applied)
{
    struct uart_config cfg;

    if (uart_config_get(USB_CONSOLE_DEV, &cfg)) {
        return;
    }

    /* usart1 has no RTS/CTS routed in the overlay. */
    cfg.flow_ctrl = UART_CFG_FLOW_CTRL_NONE;

    if (uart_config_eq(&cfg, applied)) {
        return;
    }

#if !BRIDGE_FOLLOW_HOST_LINE_CODING
    /* Report each distinct request once, so a mismatch is visible, then ignore. */
    static struct uart_config refused;

    if (!uart_config_eq(&cfg, &refused)) {
        refused = cfg;
        LOG_WRN("host asked for %u baud %u%s%s; keeping %u baud (devicetree)",
                cfg.baudrate, data_bits_n[cfg.data_bits],
                parity_s[cfg.parity], stop_bits_s[cfg.stop_bits],
                applied->baudrate);
    }
#else
    uart_irq_rx_disable(UART_DEV);

    int ret = uart_configure(UART_DEV, &cfg);
    if (ret) {
        LOG_WRN("uart_configure failed (%d), staying at %u baud",
                ret, applied->baudrate);
    } else {
        *applied = cfg;
        LOG_INF("uart config: %u baud, %u data bits, %s parity, %s stop bits",
                cfg.baudrate, data_bits_n[cfg.data_bits],
                parity_s[cfg.parity], stop_bits_s[cfg.stop_bits]);
    }

    uart_irq_rx_enable(UART_DEV);
#endif
}

/*
 * Latch the source's receiver error flags.
 *
 * Must run before uart_fifo_read(): the stm32 driver clears ORE inside the read
 * and discards it, so by then the error is gone. uart_err_check() only clears
 * flags that are actually set, so the healthy path is side-effect free; when a
 * flag is set, clearing it costs the pending byte, but on an overrun that byte
 * is lost by definition anyway.
 */
static void pipe_check_errors(struct pipe *p)
{
    if (!p->monitor_errors) {
        return;
    }

    int err = uart_err_check(p->src);
    if (err <= 0) {
        return;
    }

    if (err & UART_ERROR_OVERRUN) {
        p->overruns++;
    }
    if (err & UART_ERROR_FRAMING) {
        p->frame_errors++;
    }
    if (err & (UART_ERROR_PARITY | UART_ERROR_NOISE)) {
        p->line_errors++;
    }
}

/* Move what the source has into the ring, and wake the destination. */
static void pipe_fill(struct pipe *p)
{
    uint8_t buf[PIPE_CHUNK];

    int n = uart_fifo_read(p->src, buf, sizeof(buf));
    if (n <= 0) {
        return;
    }

    uint32_t put = ring_buf_put(p->rb, buf, n);
    if (put < (uint32_t)n) {
        p->dropped += n - put;
    }

    uart_irq_tx_enable(p->dst);

    if (ring_buf_space_get(p->rb) == 0) {
        /*
         * Nowhere to put the next byte. Stop accepting them until pipe_drain()
         * frees room; on the USB side this NAKs the host, and on the UART side
         * it keeps the RX FIFO from silently overrunning.
         */
        uart_irq_rx_disable(p->src);
    }
}

/* Push buffered bytes into the destination FIFO. */
static void pipe_drain(struct pipe *p)
{
    uint8_t *data;
    uint32_t claimed = ring_buf_get_claim(p->rb, &data, PIPE_CHUNK);

    if (claimed == 0) {
        ring_buf_get_finish(p->rb, 0);
        uart_irq_tx_disable(p->dst);
        return;
    }

    int sent = uart_fifo_fill(p->dst, data, claimed);
    ring_buf_get_finish(p->rb, sent > 0 ? sent : 0);

    /* Room again: release a source that pipe_fill() throttled. */
    if (ring_buf_space_get(p->rb) >= PIPE_RESUME) {
        uart_irq_rx_enable(p->src);
    }
}

/* Log counter movement, distinguishing where the bytes were lost. */
static void pipe_report(struct pipe *p)
{
    if (p->dropped != p->reported_dropped) {
        LOG_WRN("%s: %u bytes dropped (ring full, destination stalled)",
                p->name, p->dropped);
        p->reported_dropped = p->dropped;
    }
    if (p->overruns != p->reported_overruns) {
        LOG_WRN("%s: %u rx overruns (bytes lost at the pin, rx not serviced)",
                p->name, p->overruns);
        p->reported_overruns = p->overruns;
    }
    if (p->frame_errors != p->reported_frame_errors) {
        LOG_WRN("%s: %u framing errors (baud rate mismatch?)",
                p->name, p->frame_errors);
        p->reported_frame_errors = p->frame_errors;
    }
    if (p->line_errors != p->reported_line_errors) {
        LOG_WRN("%s: %u parity/noise errors (signal integrity?)",
                p->name, p->line_errors);
        p->reported_line_errors = p->line_errors;
    }
}

static void bridge_isr(const struct device *dev, void *ctx)
{
    struct port *port = (struct port *)ctx;

    while (uart_irq_update(dev) > 0 && uart_irq_is_pending(dev) > 0) {
        if (uart_irq_rx_ready(dev) > 0) {
            pipe_check_errors(port->in);
            pipe_fill(port->in);
        }
        if (uart_irq_tx_ready(dev) > 0) {
            pipe_drain(port->out);
        }
    }
}

int main(void)
{
    if(usb_console_init()){
        return 0;
    }

    LOG_INF("usb_console_init OK");

    struct uart_config applied;
    if (uart_config_get(UART_DEV, &applied)) {
        LOG_ERR("could not read the uart config");
        return 0;
    }

    uart_irq_callback_user_data_set(USB_CONSOLE_DEV, bridge_isr, (void *)&usb_port);
    uart_irq_callback_user_data_set(UART_DEV,        bridge_isr, (void *)&uart_port);

    uart_irq_rx_enable(USB_CONSOLE_DEV);
    uart_irq_rx_enable(UART_DEV);

    struct pipe *const pipes[] = { &usb_to_uart, &uart_to_usb };

    while (1) {
        uart_config_sync(&applied);

        for (size_t i = 0; i < ARRAY_SIZE(pipes); i++) {
            pipe_report(pipes[i]);
        }

        k_sleep(K_MSEC(100));
    }
}
