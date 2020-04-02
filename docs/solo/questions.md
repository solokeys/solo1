#Questions
## Pin Support
**1. Does SoloKey implement PIN-support?**

Yes


**2. Is the Pin stored and checked inside the SoloKey?**

The pin is stored on the key not in plain text. Only the pin hash is stored. For more information see:
 
- [Fidoallicace specification: setting new pin][fido2_new_pin] 
- [Fidoallicance specification: authentificator client pin][fido2_client_pin].


**3. What happens if someone enters a faulty pin many times?**

After **M** wrong PINs, you have to powercycle.<br>
After **N** wrong PINs, you have to fully reset the key to use it again.<br>
Constants can be find in repository under [solo/fido2/ctap.h][ctap_constants]

Actually the constants are:

- M (PIN_BOOT_ATTEMPTS):    3 times before reboot
- N (PIN_LOCKOUT_ATTEMPTS): 8 times before fully reset









[//]: # "links"
[ctap_constants]: https://github.com/solokeys/solo/blob/master/fido2/ctap.h
[fido2_new_pin]: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#settingNewPin)
[fido2_client_pin]: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorClientPIN