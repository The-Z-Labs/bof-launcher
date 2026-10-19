# Roadmap

## Milestone 1: 

[z-beac0n](https://github.com/The-Z-Labs/bof-launcher/tree/main/examples/implant) should support all the BOFs availble in [AdaptixC2 Extension Kit](https://github.com/Adaptix-Framework/Extension-Kit):

- [x] SAL-BOF
- [x] SAR-BOF
- [ ] AD-BOF
- [x] ADCS-BOF
- [ ] Creds-BOF
- [ ] Elevation-BOF
- [ ] Execution-BOF
- [ ] Injection-BOF
- [ ] LateralMovement-BOF
- [ ] Postex-BOF
- [ ] Process-BOF
- [ ] DCSync-BOF
- [ ] Kerbeus-BOF
- [ ] SQL-BOF
- [ ] LDAP-BOF

## Milestone 2:

Pipes (similar to the one in Bash shell) should be supported both on Windows and Linux.

Example (z-beac0n):

    z-beac0n> bof exec-inline <implantID> 'find --argv ./ | grep --argv shadow'

Example (cli4bofs):

    $ cli4bofs exec 'find ./ | grep shadow'

## Milestone 3:

Following core BOFs should be implemented:

1. upload
2. download
3. portfwd
4. rportfwd
5. rsocks
