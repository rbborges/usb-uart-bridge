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

#define USB_DEV  DEVICE_DT_GET(DT_CHOSEN(zephyr_console))
#define UART_DEV DEVICE_DT_GET(DT_ALIAS(uart_device))

/* ~20 ms of buffering per direction at 1 Mbaud. */
#define RING_SIZE 2048

/* CDC ACM bulk endpoint size: what the USB side moves per interrupt. */
#define USB_CHUNK 64

/* Free space that must reappear before a throttled host is resumed. */
#define USB_RESUME 256

/*
 * usart1 receives into these two buffers, ping-ponging under DMA.
 *
 * The timeout must stay 0. A non-zero value makes the driver defer the flush of
 * a partially filled buffer to a k_work, which on a request/response protocol
 * adds that delay to every frame before it reaches USB. With 0 the driver
 * instead flushes straight from the USART IDLE-line interrupt, so a short frame
 * is forwarded about one character time after the peer stops transmitting.
 */
#define UART_RX_BUF_SIZE   256
#define UART_RX_TIMEOUT_US 0

/* Upper bound on a single DMA transmit; the ring may hand back less. */
#define UART_TX_CHUNK 256

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

RING_BUF_DECLARE(usb_to_uart_rb, RING_SIZE);
RING_BUF_DECLARE(uart_to_usb_rb, RING_SIZE);

/* Counters are written from interrupt context and reported from main(). */
struct dir_stats {
    const char *name;

    uint32_t dropped;      /* ring was full: lost between the two ports */
    uint32_t overruns;     /* ORE: lost at the pin, RX not serviced in time */
    uint32_t frame_errors; /* FE: usually a baud rate mismatch */
    uint32_t line_errors;  /* parity and noise */
    uint32_t tx_refused;   /* uart_tx() rejected a transmit outright */

    uint32_t reported_dropped;
    uint32_t reported_overruns;
    uint32_t reported_frame_errors;
    uint32_t reported_line_errors;
    uint32_t reported_tx_refused;
};

static struct dir_stats uart_to_usb_stats = { .name = "uart->usb" };
static struct dir_stats usb_to_uart_stats = { .name = "usb->uart" };

static uint8_t uart_rx_buf[2][UART_RX_BUF_SIZE];
static uint8_t uart_rx_next;
static bool uart_tx_busy;

/*
 * Dwell diagnostics: the worst time data sat inside a ring during the report
 * window, and the deepest the ring got. A dwell opens when a ring goes
 * non-empty and closes when the bridge has handed everything onward (to the
 * UART DMA / to the CDC layer). If the bridge ever holds a frame for
 * milliseconds it shows up here; if these stay in microseconds while the far
 * ends time out, the delay is not in this firmware.
 *
 * dwell_end() must run with interrupts locked; dwell_begin() runs either in an
 * ISR or under the same lock. Window resets in the reporter are lock-free: a
 * clobbered sample is acceptable for diagnostics.
 */
struct dwell_stats {
    bool active;
    uint32_t t_start;    /* k_cycle_get_32() at ring empty -> non-empty */
    uint32_t max_cycles; /* worst dwell this window */
    uint32_t hiwater;    /* deepest ring fill this window, bytes */
    uint32_t over_1ms;   /* dwells that exceeded 1 ms, cumulative */
};

static struct dwell_stats usb_to_uart_dwell;
static struct dwell_stats uart_to_usb_dwell;

/* USB OUT throttling (host NAK) episodes: entered when usb_to_uart_rb fills. */
static bool usb_throttled;
static uint32_t usb_throttle_t0;
static uint32_t usb_throttles;    /* episodes, cumulative */
static uint32_t usb_throttle_max; /* longest episode this window, cycles */

static void dwell_begin(struct dwell_stats *d, uint32_t queued)
{
    if (!d->active) {
        d->active = true;
        d->t_start = k_cycle_get_32();
    }
    if (queued > d->hiwater) {
        d->hiwater = queued;
    }
}

static void dwell_end(struct dwell_stats *d)
{
    if (d->active) {
        uint32_t dt = k_cycle_get_32() - d->t_start;

        d->active = false;
        if (dt > d->max_cycles) {
            d->max_cycles = dt;
        }
        if (k_cyc_to_us_floor32(dt) > 1000) {
            d->over_1ms++;
        }
    }
}

int usb_console_init(){
    uint32_t dtr = 0;

    int ret = usb_enable(NULL);
    if (ret) {
        return ret;
    }

    /* Poll if the DTR flag was set */
    while (!dtr) {
        uart_line_ctrl_get(USB_DEV, UART_LINE_CTRL_DTR, &dtr);
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

static void uart_rx_start(void)
{
    int ret = uart_rx_enable(UART_DEV, uart_rx_buf[0], UART_RX_BUF_SIZE,
                             UART_RX_TIMEOUT_US);
    if (ret) {
        LOG_ERR("uart_rx_enable failed (%d)", ret);
        return;
    }

    uart_rx_next = 1;
}

/*
 * Reconcile the line coding the USB host asked for with the physical UART. The
 * legacy USB device stack does not report SET_LINE_CODING to the application,
 * so the CDC ACM device has to be polled for it.
 */
static void uart_config_sync(struct uart_config *applied)
{
    struct uart_config cfg;

    if (uart_config_get(USB_DEV, &cfg)) {
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
    /* Reception must be torn down and restarted around a reconfigure. */
    uart_rx_disable(UART_DEV);

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

    uart_rx_start();
#endif
}

/*
 * Start a DMA transmit on usart1 if one is not already in flight.
 *
 * The claim handed to uart_tx() stays outstanding until UART_TX_DONE, so the
 * DMA reads straight out of the ring with no intermediate copy.
 */
static void uart_tx_kick(void)
{
    unsigned int key = irq_lock();

    if (!uart_tx_busy) {
        uint8_t *data;
        uint32_t len = ring_buf_get_claim(&usb_to_uart_rb, &data, UART_TX_CHUNK);

        if (len == 0) {
            ring_buf_get_finish(&usb_to_uart_rb, 0);
            /* Ring empty and nothing in flight: the direction is drained. */
            dwell_end(&usb_to_uart_dwell);
        } else if (uart_tx(UART_DEV, data, len, SYS_FOREVER_US) == 0) {
            uart_tx_busy = true;
        } else {
            ring_buf_get_finish(&usb_to_uart_rb, 0);
            usb_to_uart_stats.tx_refused++;
        }
    }

    irq_unlock(key);

    /* A completed transmit frees space; let a throttled host resume. */
    if (ring_buf_space_get(&usb_to_uart_rb) >= USB_RESUME) {
        key = irq_lock();
        if (usb_throttled) {
            usb_throttled = false;
            uint32_t dt = k_cycle_get_32() - usb_throttle_t0;
            if (dt > usb_throttle_max) {
                usb_throttle_max = dt;
            }
        }
        irq_unlock(key);

        uart_irq_rx_enable(USB_DEV);
    }
}

/*
 * Release the finished transfer's claim and start the next one.
 *
 * The release and the flag clear share the lock: uart_tx_busy is what stops a
 * concurrent uart_tx_kick() from issuing a second claim on this ring, so it
 * must not become visible before ring_buf_get_finish() has run.
 */
static void uart_tx_complete(uint32_t len)
{
    unsigned int key = irq_lock();

    ring_buf_get_finish(&usb_to_uart_rb, len);
    uart_tx_busy = false;

    irq_unlock(key);

    uart_tx_kick();
}

static void uart_note_errors(uint32_t reason)
{
    if (reason & UART_ERROR_OVERRUN) {
        uart_to_usb_stats.overruns++;
    }
    if (reason & UART_ERROR_FRAMING) {
        uart_to_usb_stats.frame_errors++;
    }
    if (reason & (UART_ERROR_PARITY | UART_ERROR_NOISE)) {
        uart_to_usb_stats.line_errors++;
    }
}

static void uart_async_cb(const struct device *dev, struct uart_event *evt, void *ctx)
{
    ARG_UNUSED(ctx);

    switch (evt->type) {
    case UART_RX_RDY: {
        uint32_t put = ring_buf_put(&uart_to_usb_rb,
                                    evt->data.rx.buf + evt->data.rx.offset,
                                    evt->data.rx.len);
        if (put < evt->data.rx.len) {
            uart_to_usb_stats.dropped += evt->data.rx.len - put;
        }

        /* ISR context: safe against the workqueue-side dwell_end. */
        dwell_begin(&uart_to_usb_dwell, ring_buf_size_get(&uart_to_usb_rb));

        uart_irq_tx_enable(USB_DEV);
        break;
    }

    case UART_RX_BUF_REQUEST:
        /* Hand back the buffer the driver is not currently filling. */
        uart_rx_buf_rsp(dev, uart_rx_buf[uart_rx_next], UART_RX_BUF_SIZE);
        uart_rx_next ^= 1;
        break;

    case UART_RX_BUF_RELEASED:
        break;

    case UART_RX_STOPPED:
        uart_note_errors(evt->data.rx_stop.reason);
        break;

    case UART_RX_DISABLED:
        /* Reception ended, including after an error; bring it back up. */
        uart_rx_start();
        break;

    case UART_TX_DONE:
        uart_tx_complete(evt->data.tx.len);
        break;

    case UART_TX_ABORTED:
        uart_tx_complete(0);
        break;

    default:
        break;
    }
}

static void usb_rx_to_ring(const struct device *dev)
{
    uint8_t buf[USB_CHUNK];

    int n = uart_fifo_read(dev, buf, sizeof(buf));
    if (n <= 0) {
        return;
    }

    uint32_t put = ring_buf_put(&usb_to_uart_rb, buf, n);
    if (put < (uint32_t)n) {
        usb_to_uart_stats.dropped += n - put;
    }

    unsigned int key = irq_lock();
    dwell_begin(&usb_to_uart_dwell, ring_buf_size_get(&usb_to_uart_rb));
    irq_unlock(key);

    uart_tx_kick();

    if (ring_buf_space_get(&usb_to_uart_rb) == 0) {
        key = irq_lock();
        if (!usb_throttled) {
            usb_throttled = true;
            usb_throttle_t0 = k_cycle_get_32();
            usb_throttles++;
        }
        irq_unlock(key);

        /* NAK the host until the UART drains what we already hold. */
        uart_irq_rx_disable(dev);
    }
}

static void usb_tx_from_ring(const struct device *dev)
{
    uint8_t *data;
    uint32_t claimed = ring_buf_get_claim(&uart_to_usb_rb, &data, USB_CHUNK);

    if (claimed == 0) {
        ring_buf_get_finish(&uart_to_usb_rb, 0);

        /* Everything received so far has been handed to the CDC layer. */
        unsigned int key = irq_lock();
        dwell_end(&uart_to_usb_dwell);
        irq_unlock(key);

        uart_irq_tx_disable(dev);
        return;
    }

    int sent = uart_fifo_fill(dev, data, claimed);
    ring_buf_get_finish(&uart_to_usb_rb, sent > 0 ? sent : 0);
}

static void usb_isr(const struct device *dev, void *ctx)
{
    ARG_UNUSED(ctx);

    while (uart_irq_update(dev) > 0 && uart_irq_is_pending(dev) > 0) {
        if (uart_irq_rx_ready(dev) > 0) {
            usb_rx_to_ring(dev);
        }
        if (uart_irq_tx_ready(dev) > 0) {
            usb_tx_from_ring(dev);
        }
    }
}

/* Log counter movement, distinguishing where the bytes were lost. */
static void stats_report(struct dir_stats *s)
{
    if (s->dropped != s->reported_dropped) {
        LOG_WRN("%s: %u bytes dropped (ring full, destination stalled)",
                s->name, s->dropped);
        s->reported_dropped = s->dropped;
    }
    if (s->overruns != s->reported_overruns) {
        LOG_WRN("%s: %u rx overruns (bytes lost at the pin)",
                s->name, s->overruns);
        s->reported_overruns = s->overruns;
    }
    if (s->frame_errors != s->reported_frame_errors) {
        LOG_WRN("%s: %u framing errors (baud rate mismatch?)",
                s->name, s->frame_errors);
        s->reported_frame_errors = s->frame_errors;
    }
    if (s->line_errors != s->reported_line_errors) {
        LOG_WRN("%s: %u parity/noise errors (signal integrity?)",
                s->name, s->line_errors);
        s->reported_line_errors = s->line_errors;
    }
    if (s->tx_refused != s->reported_tx_refused) {
        LOG_WRN("%s: %u refused transmits", s->name, s->tx_refused);
        s->reported_tx_refused = s->tx_refused;
    }
}

/*
 * Once a second: worst in-bridge latency per direction over the last window.
 * Lock-free window resets; a clobbered sample costs one report, not data.
 */
static void dwell_report(void)
{
    uint32_t a  = usb_to_uart_dwell.max_cycles;
    uint32_t ah = usb_to_uart_dwell.hiwater;
    uint32_t b  = uart_to_usb_dwell.max_cycles;
    uint32_t bh = uart_to_usb_dwell.hiwater;
    uint32_t th = usb_throttle_max;

    usb_to_uart_dwell.max_cycles = 0;
    usb_to_uart_dwell.hiwater = 0;
    uart_to_usb_dwell.max_cycles = 0;
    uart_to_usb_dwell.hiwater = 0;
    usb_throttle_max = 0;

    if (a || b) {
        LOG_INF("dwell max: usb->uart %u us (peak %u B), uart->usb %u us (peak %u B), >1ms %u/%u",
                k_cyc_to_us_floor32(a), ah,
                k_cyc_to_us_floor32(b), bh,
                usb_to_uart_dwell.over_1ms, uart_to_usb_dwell.over_1ms);
    }
    if (th) {
        LOG_WRN("usb rx throttled: %u episodes total, longest this window %u us",
                usb_throttles, k_cyc_to_us_floor32(th));
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

    int ret = uart_callback_set(UART_DEV, uart_async_cb, NULL);
    if (ret) {
        LOG_ERR("uart_callback_set failed (%d)", ret);
        return 0;
    }

    uart_irq_callback_user_data_set(USB_DEV, usb_isr, NULL);

    uart_rx_start();
    uart_irq_rx_enable(USB_DEV);

    struct dir_stats *const stats[] = { &usb_to_uart_stats, &uart_to_usb_stats };
    unsigned int tick = 0;

    while (1) {
        if (++tick >= 10) {
            tick = 0;
            dwell_report();
        }

        /*
         * Backstop. Transmits are normally chained from UART_TX_DONE, but if
         * uart_tx() were ever refused the claim is dropped and nothing would
         * re-arm until the next byte arrived from USB. This bounds that to one
         * poll interval instead of stranding the data indefinitely.
         */
        uart_tx_kick();

        uart_config_sync(&applied);

        for (size_t i = 0; i < ARRAY_SIZE(stats); i++) {
            stats_report(stats[i]);
        }

        k_sleep(K_MSEC(100));
    }
}
