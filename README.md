1Password + Yubikey Unlock
==========================

This tool allows you to unlock your 1Password 7 for Windows using a PGP
encrypted password, with the private key stored inside an YubiKey.


What's necessary?
-----------------

- 1Password 7 for Windows (It does NOT work with the latest 1Password 8!)
- A YubiKey with PGP support - Check [compatible devices here](1)
- OpenPGP keys setup and ssh agent properly configured - Check [guide here](2)
- [Gpg4win](3)
- [Microsoft Visual Studio](4) 2019 or newer for compiling

Before you start, it's highly recommended to test if you're able to encrypt and
decrypt messages using your YubiKey and gpg.
Open a command prompt and try these commands:
```
gpg -K
echo my test message | gpg --encrypt --armor -r YOUR_KEY_ID > test.txt
type test.txt
gpg --decrypt test.txt
del test.txt
```

NOTE: If those commands seems daunting for you, I recommend you take a break
and research what they do before proceeding!


How to build your own unlocking application
-------------------------------------------

- Clone this repository
- Run the following command, adapted to your needs. You will need it in the
  next few steps:
```
echo MY_PASSWORD | gpg --encrypt --armor -r YOUR_KEY_ID | gpg --encrypt --armor -r YOUR_KEY_ID
```
- Edit [PassUnlock/PassUnlock.cpp]
- Search for `constexpr char encrypted_data[]`
- Replace `ADD_DATA_HERE` entries with the encrypted password your got above.
  Make sure to add or remove lines as needed, so it matches the output exactly.
  New lines should use the `\n` character.
- Save your changes
- Change the project to your platform (usually x64) and set it to Release build.
- Compile the project using Visual Studio


Usage
-----

- With 1Password 7 running on the tray and locked, run `PassUnlock.exe` built
 cal in the previous step
- If everything is correct, you will be prompted your YubiKey PGP password.
- After entering your password, you will see a 15 seconds timeout.
- Before it times out, press `Ctrl + Shift + \` to open the unlock window.
- Done!

IMPORTANT: If you're using powershell, be sure to use [Clear-History](5) to
make sure no important data is left in its history!


[1]: https://support.yubico.com/hc/en-us/articles/360013790259-Using-Your-YubiKey-with-OpenPGP
[2]: https://github.com/drduh/YubiKey-Guide
[3]: https://www.gpg4win.org/
[4]: https://visualstudio.microsoft.com/vs/community/
[5]: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/clear-history
