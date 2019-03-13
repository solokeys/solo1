# On modern systems, udev has a TAG uaccess, which is used in 73-seat-late.rules
# On older systems, we use GROUP plugdev with MODE
# --> Try `make setup` first, if it doesn't work, try `make legacy-setup`.
#
# The symlinks are optional, install with `make symlinks`.
#
# We keep 99-solo.rules in the parent directory but deprecate it,
# remove when documentation is updated.


setup: install activate
legacy-setup: install-legacy activate

# Symlinks can be setup, we don't officially supply any
# symlinks: install-symlinks activate

RULES_PATH=/etc/udev/rules.d

activate:
	sudo udevadm control --reload-rules
	sudo udevadm trigger

install:
	sudo cp $(PWD)/70-solokeys-access.rules ${RULES_PATH}/70-solokeys-access.rules

install-legacy:
	sudo cp $(PWD)/70-solokeys-legacy-access.rules ${RULES_PATH}/70-solokeys-access.rules

# install-symlinks:
# 	sudo cp $(PWD)/71-solokeys-symlinks.rules ${RULES_PATH}/71-solokeys-symlinks.rules

# The ID_MM_DEVICE_IGNORE tag in our udev rules are ignored
# if ModemManager is running with "strict" filter policy.
# Debian Buster for instance does this.
# One solution is to run ModemManager with "paranoid" filter policy.
paranoid-modemmanager: dropin-paranoid-modemmanager restart-modemmanager
dropin-paranoid-modemmanager:
	test -f /usr/sbin/ModemManager && sudo cp ModemManager-override.conf /etc/systemd/system/ModemManager.service.d/override.conf

strict-modemmanager: dropin-strict-modemmanager restart-modemmanager
dropin-strict-modemmanager:
	sudo rm -f /etc/systemd/system/ModemManager.service.d/override.conf

restart-modemmanager:
	sudo systemctl daemon-reload
	sudo systemctl restart ModemManager.service
