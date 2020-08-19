#
# Makefile for the sensor drivers.
#

# Each configuration option enables a list of files.
obj-$(CONFIG_SENSORS_SSP)		+= sensors_core.o ssp_dev.o ssp_spi.o ssp_data.o ssp_sysfs.o \
						ssp_iio.o ssp_firmware.o ssp_debug.o ssp_sensorhub.o \
						ssp_misc.o factory/
obj-$(CONFIG_SENSORS_SX9310)		+= sx9310.o