# REFS-PUBLIC.md - Public References

> Record external public repositories, datasets, documentation, APIs, or other
> public resources that this repository utilizes or depends on.
> This file is tracked and intentionally kept free of private or local-only details.

## Public Repositories

- No fixed external code repository is the main upstream; the repo automates installed NordVPN clients and CLIs.

## Public Datasets and APIs

- No standing public data API is required; operations target the locally installed NordVPN Windows app or Linux CLI.

## Documentation and Specifications

- https://nordvpn.com/download/windows/ - Windows app distribution referenced by the `NordVPN.exe` backend
- https://nordvpn.com/download/linux/ - Linux CLI distribution referenced by the `nordvpn` backend
- https://support.nordvpn.com/ - general NordVPN support documentation for client behavior and troubleshooting

## Notes

- Authenticated VPN actions use local credentials and installed binaries, so public refs are limited to the vendor's published client and support docs.
