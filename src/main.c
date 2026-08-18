/*
 * Low-latency USB CDC-ACM <-> UART bridge.
 *
 * Both directions are buffered in ring buffers and moved by DMA (UART side) or
 * bulk transfers (USB side). Nothing coalesces or waits on a timer: data is
 * forwarded as soon as the receiving end signals it has some.
 *
 * The UART receives under DMA with an idle-line flush, so a short burst is
 * handed on roughly one character time after the peer stops transmitting,
 * while a continuous stream never risks an overrun.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/ring_buffer.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(usb_uart_bridge, LOG_LEVEL_INF);

#define USB_DEV  DEVICE_DT_GET(DT_CHOSEN(zephyr_console))
#define UART_DEV DEVICE_DT_GET(DT_ALIAS(uart_device))

/* Buffering per direction. 2 KB is ~20 ms of slack at 1 Mbaud. */
#define RING_SIZE 2048

/* CDC ACM bulk endpoint size: what the USB side moves per interrupt. */
#define USB_CHUNK 64

/* Free space that must reappear before a throttled host is resumed. */
#define USB_RESUME 256

/*
 * The UART receives into these two buffers, ping-ponging under DMA.
 *
 * The timeout must stay 0. A non-zero value makes the driver defer the flush
 * of a partially filled buffer to a k_work, adding that delay to every short
 * frame. With 0 the driver flushes straight from the USART idle-line
 * interrupt instead, which is what keeps the forwarding latency at the
 * microsecond scale rather than the millisecond scale.
 */
/* DIAGNOSTIC: temporarily 64 (normally 256) to confirm that the lost
 * byte is tied to the DMA buffer switch. Revert to 256 afterwards. */
#define UART_RX_BUF_SIZE   64
#define UART_RX_TIMEOUT_US 0

/* Upper bound on a single DMA transmit; the ring may hand back less. */
#define UART_TX_CHUNK 256

/*
 * Apply the line coding (baud rate, parity, data bits, stop bits) that the USB
 * host requests, like any USB-serial adapter does. Set to 0 to pin the UART to
 * the devicetree current-speed and ignore the host instead, which is useful
 * when the attached peer runs at a fixed rate that must not be disturbed.
 *
 * Note that the CDC ACM class resets its line coding to 115200 on every USB
 * reset, so with this enabled the UART follows suit until the host reopens the
 * port and sets the rate it wants.
 */
#define BRIDGE_FOLLOW_HOST_LINE_CODING 1

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
    uint32_t throttles;    /* times the source was paused for backpressure */

    uint32_t reported_dropped;
    uint32_t reported_overruns;
    uint32_t reported_frame_errors;
    uint32_t reported_line_errors;
    uint32_t reported_tx_refused;
    uint32_t reported_throttles;
};

static struct dir_stats uart_to_usb_stats = { .name = "uart->usb" };
static struct dir_stats usb_to_uart_stats = { .name = "usb->uart" };

/*
 * Forwarding latency: the time data waits in the bridge before being handed to
 * the far side. It deliberately excludes the time the UART then spends
 * serializing at wire rate, which is a property of the baud rate rather than
 * of this firmware.
 */
static uint32_t u2h_since;   /* uart->usb: set when a ring goes non-empty */
static bool u2h_pending;
static uint32_t u2h_max;
static uint32_t h2u_since;   /* usb->uart: set when a transmit becomes due */
static bool h2u_pending;
static uint32_t h2u_max;

static uint8_t uart_rx_buf[2][UART_RX_BUF_SIZE];
static uint8_t uart_rx_next;
static bool uart_tx_busy;
static bool usb_throttled;

/*
 * Set when uart_tx() is refused. The stm32 driver can fail a transmit with its
 * DMA stream still marked busy and never clear that by itself, so every later
 * transmit fails the same way and the direction stays dead with data piling up
 * in the ring. A watchdog forces the teardown the driver skipped.
 */
static volatile bool uart_tx_stuck;

/*
 * RX health. The stm32 async driver has a path (DMA error -> UART_RX_STOPPED)
 * that halts reception without ever raising UART_RX_DISABLED, so a restart
 * keyed on RX_DISABLED alone can leave the bridge deaf with no indication.
 * These let a watchdog in the main loop detect and break that state.
 */
static volatile bool uart_rx_alive;
static volatile bool uart_rx_stop_seen;
static bool uart_rx_inhibit; /* a deliberate teardown is in progress */
static uint32_t uart_rx_restarts;
static uint32_t reported_rx_restarts;
static int uart_rx_last_err;

static K_SEM_DEFINE(uart_rx_off, 0, 1);

static const uint8_t data_bits_n[]     = {5, 6, 7, 8, 9};
static const char *const parity_s[]    = {"none", "odd", "even", "mark", "space"};
static const char *const stop_bits_s[] = {"0.5", "1", "1.5", "2"};

static void uart_rx_start(void)
{
    int ret = uart_rx_enable(UART_DEV, uart_rx_buf[0], UART_RX_BUF_SIZE,
                             UART_RX_TIMEOUT_US);
    if (ret) {
        uart_rx_alive = false;
        /* Log once per failure mode; the watchdog retries every 100 ms. */
        if (ret != uart_rx_last_err) {
            LOG_ERR("uart_rx_enable failed (%d)", ret);
        }
        uart_rx_last_err = ret;
        return;
    }

    if (uart_rx_last_err) {
        LOG_INF("uart rx recovered");
    }
    uart_rx_last_err = 0;
    uart_rx_next = 1;
    uart_rx_stop_seen = false;
    uart_rx_alive = true;
}

/*
 * Start a DMA transmit on the UART if one is not already in flight.
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
        } else if (uart_tx(UART_DEV, data, len, SYS_FOREVER_US) == 0) {
            uart_tx_busy = true;

            if (h2u_pending) {
                uint32_t dt = k_cycle_get_32() - h2u_since;

                h2u_pending = false;
                if (dt > h2u_max) {
                    h2u_max = dt;
                }
            }
        } else {
            ring_buf_get_finish(&usb_to_uart_rb, 0);
            usb_to_uart_stats.tx_refused++;
            uart_tx_stuck = true;
        }
    }

    irq_unlock(key);

    /* A completed transmit frees space; let a throttled host resume. */
    if (usb_throttled && ring_buf_space_get(&usb_to_uart_rb) >= USB_RESUME) {
        usb_throttled = false;
        uart_irq_rx_enable(USB_DEV);
    }
}

/* Restart the flow from a thread, never from the driver's own callback. */
static void uart_tx_pump(struct k_work *work)
{
    ARG_UNUSED(work);
    uart_tx_kick();
}

static K_WORK_DEFINE(uart_tx_work, uart_tx_pump);

/*
 * Release the finished transfer's claim and start the next one.
 *
 * The release and the flag clear share the lock: uart_tx_busy is what stops a
 * concurrent uart_tx_kick() from issuing a second claim on this ring, so it
 * must not become visible before ring_buf_get_finish() has run.
 *
 * The next transmit is deferred to a work item rather than started here. This
 * runs from the driver's UART_TX_DONE callback, which is reached from the DMA
 * completion path before the driver has released the stream, so a uart_tx()
 * issued from here is refused with -EBUSY and wedges the direction. Only a
 * continuation of an already-running burst pays the work-queue hop; the first
 * transmit of a burst still goes straight out from the USB interrupt, so short
 * frames keep their latency.
 */
static void uart_tx_complete(uint32_t len)
{
    unsigned int key = irq_lock();

    ring_buf_get_finish(&usb_to_uart_rb, len);
    uart_tx_busy = false;

    /* More queued: the gap until the next uart_tx() is bridge-added time. */
    if (!ring_buf_is_empty(&usb_to_uart_rb) && !h2u_pending) {
        h2u_pending = true;
        h2u_since = k_cycle_get_32();
    }

    irq_unlock(key);

    k_work_submit(&uart_tx_work);
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

        if (!u2h_pending) {
            u2h_pending = true;
            u2h_since = k_cycle_get_32();
        }

        /* Data still flowing: reception did not die with the last error. */
        uart_rx_stop_seen = false;

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
        /* May be the driver's dead-end DMA-error path; watchdog decides. */
        uart_rx_stop_seen = true;
        break;

    case UART_RX_DISABLED:
        uart_rx_alive = false;
        if (uart_rx_inhibit) {
            k_sem_give(&uart_rx_off);
        } else {
            /* Reception ended on its own, including after an error. */
            uart_rx_restarts++;
            uart_rx_start();
        }
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
    if (!uart_tx_busy && !h2u_pending) {
        h2u_pending = true;
        h2u_since = k_cycle_get_32();
    }
    irq_unlock(key);

    uart_tx_kick();

    if (ring_buf_space_get(&usb_to_uart_rb) == 0) {
        /* NAK the host until the UART drains what we already hold. */
        usb_throttled = true;
        usb_to_uart_stats.throttles++;
        uart_irq_rx_disable(dev);
    }
}

static void usb_tx_from_ring(const struct device *dev)
{
    uint8_t *data;
    uint32_t claimed = ring_buf_get_claim(&uart_to_usb_rb, &data, USB_CHUNK);

    if (claimed == 0) {
        ring_buf_get_finish(&uart_to_usb_rb, 0);
        uart_irq_tx_disable(dev);
        return;
    }

    int sent = uart_fifo_fill(dev, data, claimed);
    ring_buf_get_finish(&uart_to_usb_rb, sent > 0 ? sent : 0);

    if (sent > 0 && u2h_pending && ring_buf_is_empty(&uart_to_usb_rb)) {
        uint32_t dt = k_cycle_get_32() - u2h_since;

        u2h_pending = false;
        if (dt > u2h_max) {
            u2h_max = dt;
        }
    }
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

static bool uart_config_eq(const struct uart_config *a, const struct uart_config *b)
{
    return a->baudrate  == b->baudrate  &&
           a->parity    == b->parity    &&
           a->stop_bits == b->stop_bits &&
           a->data_bits == b->data_bits &&
           a->flow_ctrl == b->flow_ctrl;
}

/*
 * Reconcile the line coding the USB host asked for with the UART. The legacy
 * USB device stack does not report SET_LINE_CODING to the application, so the
 * CDC ACM device has to be polled for it.
 */
static void uart_config_sync(struct uart_config *applied)
{
    struct uart_config cfg;

    if (uart_config_get(USB_DEV, &cfg)) {
        return;
    }

    /* Hardware flow control needs RTS/CTS pins, which are not routed. */
    cfg.flow_ctrl = UART_CFG_FLOW_CTRL_NONE;

    if (uart_config_eq(&cfg, applied)) {
        return;
    }

#if !BRIDGE_FOLLOW_HOST_LINE_CODING
    /* Report each distinct request once, so a mismatch is visible, then ignore. */
    static struct uart_config refused;

    if (!uart_config_eq(&cfg, &refused)) {
        refused = cfg;
        LOG_WRN("host asked for %u baud; keeping %u baud (devicetree)",
                cfg.baudrate, applied->baudrate);
    }
#else
    /* Tear reception down around the reconfigure without the auto-restart. */
    uart_rx_inhibit = true;
    k_sem_reset(&uart_rx_off);
    if (uart_rx_disable(UART_DEV) == 0) {
        k_sem_take(&uart_rx_off, K_MSEC(50));
    }

    int ret = uart_configure(UART_DEV, &cfg);
    if (ret) {
        LOG_WRN("uart_configure failed (%d), staying at %u baud",
                ret, applied->baudrate);
    } else {
        *applied = cfg;
        LOG_INF("uart: %u baud, %u data bits, %s parity, %s stop bits",
                cfg.baudrate, data_bits_n[cfg.data_bits],
                parity_s[cfg.parity], stop_bits_s[cfg.stop_bits]);
    }

    uart_rx_inhibit = false;
    uart_rx_start();
#endif
}

/*
 * Runs every 100 ms. Recovers reception from the two states the event handlers
 * cannot: a dead DMA (RX_STOPPED never followed by RX_DISABLED) and a failed
 * uart_rx_enable(), at boot or during a restart.
 */
static void uart_rx_watchdog(void)
{
    if (uart_rx_alive && uart_rx_stop_seen) {
        uart_rx_stop_seen = false;
        /* Tear down properly; RX_DISABLED will trigger the restart. */
        if (uart_rx_disable(UART_DEV) != 0) {
            uart_rx_alive = false;
        }
    } else if (!uart_rx_alive) {
        uart_rx_restarts++;
        uart_rx_start();
    }

    if (uart_rx_restarts != reported_rx_restarts) {
        LOG_WRN("uart rx restarted (%u total, last err %d)",
                uart_rx_restarts, uart_rx_last_err);
        reported_rx_restarts = uart_rx_restarts;
    }
}

/*
 * Runs every 100 ms. Recovers the one state uart_tx_kick() cannot: a transmit
 * refused because the driver left its DMA stream busy. Nothing retries on its
 * own, so without this the usb->uart direction never comes back. uart_tx_abort()
 * forces the driver to release the stream; any resulting UART_TX_ABORTED runs
 * uart_tx_complete() and restarts the flow, and if none arrives the kick here
 * does it instead.
 */
static void uart_tx_watchdog(void)
{
    if (!uart_tx_stuck) {
        return;
    }
    uart_tx_stuck = false;

    if (uart_tx_busy || ring_buf_is_empty(&usb_to_uart_rb)) {
        return;
    }

    /* Once only: stats_report() already tracks the refusal count, and the
     * watchdog retries at 10 Hz for as long as the condition lasts. */
    static bool announced;

    if (!announced) {
        announced = true;
        LOG_WRN("usb->uart: forcing dma teardown after a refused transmit");
    }

    (void)uart_tx_abort(UART_DEV);
    uart_tx_kick();
}

static void stats_report(struct dir_stats *s)
{
    if (s->dropped != s->reported_dropped) {
        LOG_WRN("%s: %u bytes dropped (buffer full)", s->name, s->dropped);
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
    if (s->throttles != s->reported_throttles) {
        LOG_WRN("%s: %u backpressure pauses (peer slower than source)",
                s->name, s->throttles);
        s->reported_throttles = s->throttles;
    }
}

/* Once a second: worst forwarding latency per direction over the last window. */
static void latency_report(void)
{
    uint32_t a = h2u_max;
    uint32_t b = u2h_max;

    h2u_max = 0;
    u2h_max = 0;

    if (a || b) {
        LOG_INF("forwarding latency: usb->uart %u us, uart->usb %u us",
                k_cyc_to_us_floor32(a), k_cyc_to_us_floor32(b));
    }
}

int main(void)
{
    int ret = usb_enable(NULL);
    if (ret) {
        LOG_ERR("usb_enable failed (%d)", ret);
        return 0;
    }

    struct uart_config applied;
    if (uart_config_get(UART_DEV, &applied)) {
        LOG_ERR("could not read the uart config");
        return 0;
    }

    ret = uart_callback_set(UART_DEV, uart_async_cb, NULL);
    if (ret) {
        LOG_ERR("uart_callback_set failed (%d)", ret);
        return 0;
    }

    uart_irq_callback_user_data_set(USB_DEV, usb_isr, NULL);

    uart_rx_start();
    uart_irq_rx_enable(USB_DEV);

    LOG_INF("bridge up: %u baud, dma rx %u B x2, %u B buffers",
            applied.baudrate, UART_RX_BUF_SIZE, RING_SIZE);

    struct dir_stats *const stats[] = { &usb_to_uart_stats, &uart_to_usb_stats };
    unsigned int tick = 0;

    while (1) {
        if (++tick >= 10) {
            tick = 0;
            latency_report();
        }

        uart_rx_watchdog();
        uart_tx_watchdog();
        uart_config_sync(&applied);

        for (size_t i = 0; i < ARRAY_SIZE(stats); i++) {
            stats_report(stats[i]);
        }

        k_sleep(K_MSEC(100));
    }
}
