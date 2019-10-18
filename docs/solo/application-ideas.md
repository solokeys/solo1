# Using Solo for passwordless or second factor login on Linux 

## Setup on Ubuntu 18.04
Before you can use Solo for passwordless or second factor login in your Linux system you have to install some packages.

This was tested under **Linux Mint 19.2**.

First you have to install PAM modules for u2f.

```
  sudo apt install libpam-u2f pamu2fcfg
```

## Setting up key
To use Solo as passwordless or second factor login, you have to setup your system with your Solo.
First create a new folder named **Yubico** in your **.config** folder in your **home** directory

```
  mkdir ~/.config/Yubico
```

Then create a new key for PAM U2F module. If it is your first key you want to register use following command:
```
  pamu2fcfg > ~/.config/Yubico/u2f_keys
```
If you want to register an additional key use this command instead:
```
  pamu2fcfg >> ~/.config/Yubico/u2f_keys
```
Now press the button on your Solo.
 

If you can't generate your key (error message), you may add Yubico Team from PPA and install latest libpam-u2f and pamu2fcfg and try again.
```
  sudo add-apt-repository ppa:yubico/stable
  sudo apt-get update
  sudo apt-get upgrade
```


## Login into Linux
### Passwordless
To login passwordless into your Linux system, you have to edit the file **lightdm** (or **gdm** or which display manager you prefered).
In case of lightdm:

```
sudo vim /etc/pam.d/lightdm
```
Now search following entry:
```
@include common-auth
```
and add
```
auth    sufficient      pam_u2f.so
```
**before** @include common-auth.

Save the file and test it.<br>
Insert Solo in your USB port and logout.
Now you should be able to login into Linux without password, only with pressing your button on Solo and press enter.

Why **sufficient**? The difference between the keyword sufficient and required is, if you don't have your Solo available, you can also login, because the system falls back to password mode.


The login mechanism can be also used for additional features like:

:  - Login after screen timeout - edit /etc/pam.d/mate-screensaver (or kde-screensaver, ...)
  - Passwordless sudo - edit /etc/pam.d/sudo

Check out your folder **/etc/pam.d/** and do some experiments.

**But remember:** <br>
The login passwordless won't make your system more secure, but maybe more comfortable. If somebody have access to your Solo, this person will be also able to login into your system.


### Solo as second factor
To use Solo as second factor, for login into your Linux system, is nearly the same.

```
sudo vim /etc/pam.d/lightdm
```
Now search following entry:
```
@include common-auth
```
and add
```
auth    required      pam_u2f.so
```
**after** @include common-auth.

Save the file and test it. <br>
In case your Solo is not present, your password will be incrorrect. If Solo is plugged into your USB port, it will signal pressing the button and you will be able to login into Linux.

Why **required**? If you choose the option **sufficent** your Solo is optional. You could also login without second factor if your Solo is not connected.

**But remember:**<br>
If you loose your Solo you won't be able to login into your system.
