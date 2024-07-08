#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(mdio_adin6310, CONFIG_ETHERNET_LOG_LEVEL);
#define DT_DRV_COMPAT adi_adin6310_mdio

#include <zephyr/kernel.h>
#include <stdio.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/spi.h>
#include "zephyr/sys/util.h"

#include <zephyr/net/net_pkt.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/phy.h>
#include <zephyr/drivers/mdio.h>

#include "SMP_stack_api.h"
#include "SES_port_api.h"
#include "SES_codes.h"
#include "SES_switch.h"
#include "SES_event.h"
#include "SES_frame_api.h"
#include "SES_interface_management.h"

struct mdio_adin6310_config {
        int32_t id;
        const struct device *adin;
};

static void mdio_adin6310_bus_enable(const struct device *dev)
{
}

static void mdio_adin6310_bus_disable(const struct device *dev)
{
}

static int mdio_adin6310_read_c45(const struct device *dev, uint8_t prtad,
				  uint8_t devad, uint16_t regad,
				  uint16_t *data)
{
        int ret;
        uint32_t addr;

        addr = (devad << 16) | regad;
	ret = SES_ReadPhyReg(SES_macPort2, addr, data);
        if (ret)
                return ret;

        return 0;
}

static int mdio_adin6310_write_c45(const struct device *dev, uint8_t prtad,
				   uint8_t devad, uint16_t regad,
				   uint16_t data)
{
        int ret;
        uint32_t addr;

        addr = (devad << 16) | regad;
	ret = SES_WritePhyReg(SES_macPort2, addr, data);
        if (ret)
                return ret;

	return 0;
}

static int mdio_adin6310_read(const struct device *dev, uint8_t prtad,
			      uint8_t regad, uint16_t *data)
{
	return SES_ReadPhyReg(prtad, regad, data);
}

static int mdio_adin6310_write(const struct device *dev, uint8_t prtad,
			      uint8_t regad, uint16_t data)
{
	return SES_WritePhyReg(prtad, regad, data);
}


static int mdio_adin6310_init(const struct device *dev)
{
	printf("INIT MDIO\n");

        return 0;
}

static const struct mdio_driver_api mdio_adin6310_api = {
        .read = mdio_adin6310_read,
        .write = mdio_adin6310_write,
        .bus_enable = mdio_adin6310_bus_enable,
        .bus_disable = mdio_adin6310_bus_disable,
        .read_c45 = mdio_adin6310_read_c45,
	.write_c45 = mdio_adin6310_write_c45,
};

#define ADIN6310_MDIO_INIT(n)							\
	static const struct mdio_adin6310_config mdio_adin6310_config_##n = {	\
		.adin = DEVICE_DT_GET(DT_INST_BUS(n)),				\
	};									\
	DEVICE_DT_INST_DEFINE(n, &mdio_adin6310_init, NULL,			\
			      NULL, &mdio_adin6310_config_##n,			\
			      POST_KERNEL, CONFIG_MDIO_INIT_PRIORITY,		\
			      &mdio_adin6310_api);

DT_INST_FOREACH_STATUS_OKAY(ADIN6310_MDIO_INIT)