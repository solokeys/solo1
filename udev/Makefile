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
