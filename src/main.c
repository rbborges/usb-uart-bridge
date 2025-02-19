/*
 * Copyright (c) 2016 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(usb_uart_bridge_main, LOG_LEVEL_INF);

#define USB_CONSOLE_DEV DEVICE_DT_GET(DT_CHOSEN(zephyr_console))
#define UART_DEV        DEVICE_DT_GET(DT_ALIAS(uart_device))

struct uart_passthrough_data {
    const uint8_t * const name;

    const struct device *rx_dev;
    bool rx_error;
    bool rx_overflow;

    const struct device *tx_dev;
};

struct uart_passthrough_data usb_console = {
    .name = "usb_console",

    .rx_dev      = USB_CONSOLE_DEV,
    .rx_error    = false,
    .rx_overflow = false,

    .tx_dev      = UART_DEV,
};

struct uart_passthrough_data uart = {
    .name = "uart",

    .rx_dev      = UART_DEV,
    .rx_error    = false,
    .rx_overflow = false,

    .tx_dev      = USB_CONSOLE_DEV,
};

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

static void uart_cb(const struct device *dev, void *ctx)
{
    struct uart_passthrough_data *uart_ctx = (struct uart_passthrough_data *)ctx;

    while (uart_irq_update(uart_ctx->rx_dev) > 0) {
        int ret;
        ret = uart_irq_rx_ready(uart_ctx->rx_dev);
        if (ret < 0) {
            uart_ctx->rx_error = true;
        }
        if (ret <= 0) {
            return;
        }

        uint8_t c;
        ret = uart_fifo_read(uart_ctx->rx_dev, &c, 1);
        while( ret > 0 ){
            if(uart_irq_update(uart_ctx->tx_dev) > 0){
                uart_fifo_fill(uart_ctx->tx_dev, &c, 1);
            }
            ret = uart_fifo_read(uart_ctx->rx_dev, &c, 1);
        }
        if (ret < 0) {
            uart_ctx->rx_error = true;
        }
        if (ret <= 0) {
            return;
        }
    }
}

int main(void)
{
    if(usb_console_init()){
        return 0;
    }

    LOG_INF("usb_console_init OK");

    uart_irq_callback_user_data_set(usb_console.rx_dev, uart_cb, (void *)&usb_console);
    uart_irq_callback_user_data_set(uart.rx_dev,        uart_cb, (void *)&uart);

    uart_irq_rx_enable(usb_console.rx_dev);
    uart_irq_rx_enable(uart.rx_dev);


    while (1) {
        k_sleep(K_SECONDS(1));
    }
}
