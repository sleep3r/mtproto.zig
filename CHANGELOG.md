# Changelog

## [0.5.1](https://github.com/sleep3r/mtproto.zig/compare/v0.5.0...v0.5.1) (2026-04-04)


### Bug Fixes

* enforce strict max_connections reservation before spawn ([#56](https://github.com/sleep3r/mtproto.zig/issues/56)) ([74db0c3](https://github.com/sleep3r/mtproto.zig/commit/74db0c3b88a4ce5acf865792ccff1e1a011e6679))


### Performance Improvements

* apply dynamic record sizing and connection backlog scaling ([#53](https://github.com/sleep3r/mtproto.zig/issues/53)) ([e62b56e](https://github.com/sleep3r/mtproto.zig/commit/e62b56e278b50ad10755f93ee9b6f4bc64c9e7c6))

## [0.5.0](https://github.com/sleep3r/mtproto.zig/compare/v0.4.1...v0.5.0) (2026-04-05)

### Features

* **docs:** remove extra capacity columns from root benchmark table for better readability

## [0.4.1](https://github.com/sleep3r/mtproto.zig/compare/v0.4.0...v0.4.1) (2026-04-04)


### Bug Fixes

* add stability harness and tune middleproxy buffers ([#47](https://github.com/sleep3r/mtproto.zig/issues/47)) ([4e98bbe](https://github.com/sleep3r/mtproto.zig/commit/4e98bbeb293c95ef9a74e8ce780fe180156d27e5))

## [0.4.0](https://github.com/sleep3r/mtproto.zig/compare/v0.3.1...v0.4.0) (2026-04-04)


### Features

* Add Dockerfile and build instructions ([#16](https://github.com/sleep3r/mtproto.zig/issues/16)) ([ba13e35](https://github.com/sleep3r/mtproto.zig/commit/ba13e35d203fe367f0035d96d096805bd6a016b6))
* soak gate CI + re-enable DRS with config toggle ([#45](https://github.com/sleep3r/mtproto.zig/issues/45)) ([e1435a8](https://github.com/sleep3r/mtproto.zig/commit/e1435a8a56918135e0812d2534a88dc36459b69d))

## [0.3.1](https://github.com/sleep3r/mtproto.zig/compare/v0.3.0...v0.3.1) (2026-04-03)


### Bug Fixes

* support IPv4-only hosts (no IPv6 required) ([#42](https://github.com/sleep3r/mtproto.zig/issues/42)) ([ca3e563](https://github.com/sleep3r/mtproto.zig/commit/ca3e56362bcf9a4fa6a50d2b872a47d55b79d053)), closes [#39](https://github.com/sleep3r/mtproto.zig/issues/39)

## [0.3.0](https://github.com/sleep3r/mtproto.zig/compare/v0.2.2...v0.3.0) (2026-04-03)


### Features

* make tcp listen backlog configurable ([#38](https://github.com/sleep3r/mtproto.zig/issues/38)) ([e6bb285](https://github.com/sleep3r/mtproto.zig/commit/e6bb285801dab0bd671a25a3625c87ec1a125437))


### Bug Fixes

* **proxy:** stabilize Ubuntu reconnect and MiddleProxy routing ([#36](https://github.com/sleep3r/mtproto.zig/issues/36)) ([4ec90b0](https://github.com/sleep3r/mtproto.zig/commit/4ec90b0fbc6362bbec0edc67fe004c5df7e7c7d8))

## [0.2.2](https://github.com/sleep3r/mtproto.zig/compare/v0.2.1...v0.2.2) (2026-04-02)


### Bug Fixes

* **middleproxy:** assert computed C2S frame size ([#31](https://github.com/sleep3r/mtproto.zig/issues/31)) ([6ced4b3](https://github.com/sleep3r/mtproto.zig/commit/6ced4b32f5e4ac5925e3372c57223414cce254b3))
* **proxy:** increase max_connections to 65535 ([#27](https://github.com/sleep3r/mtproto.zig/issues/27)) ([52a9fc4](https://github.com/sleep3r/mtproto.zig/commit/52a9fc4f5ff6622740fdc8d5c68f73d53f3555c5)), closes [#26](https://github.com/sleep3r/mtproto.zig/issues/26)

## [0.2.1](https://github.com/sleep3r/mtproto.zig/compare/v0.2.0...v0.2.1) (2026-04-02)


### Bug Fixes

* respect mask_port for local masking and ignore .vscode ([#24](https://github.com/sleep3r/mtproto.zig/issues/24)) ([b4a5030](https://github.com/sleep3r/mtproto.zig/commit/b4a50303e1035d912bc46c8f61aba75396b64172))

## [0.2.0](https://github.com/sleep3r/mtproto.zig/compare/v0.1.0...v0.2.0) (2026-04-02)


### Features

* **deploy:** add automate migrate command to push existing config to new servers ([5c96c4e](https://github.com/sleep3r/mtproto.zig/commit/5c96c4e89a0225d948389780d64d4a7ef1a7c17b))
* **deploy:** add optional Cloudflare DNS update to migration script ([ccfc6a4](https://github.com/sleep3r/mtproto.zig/commit/ccfc6a46c15f3dacb55f658ccaaa2e745208447a))
* **deploy:** add safe in-place server update flow ([#23](https://github.com/sleep3r/mtproto.zig/issues/23)) ([2bdf27a](https://github.com/sleep3r/mtproto.zig/commit/2bdf27a2b9706d4db237395fd94395f490b2a894))
* **deploy:** automate zero-RTT masking and OS-level tcp desync ([c7838c8](https://github.com/sleep3r/mtproto.zig/commit/c7838c85b880164d04a56b6c5c86889223239420))
* **deploy:** extract DNS update into a standalone make target ([69ddfa0](https://github.com/sleep3r/mtproto.zig/commit/69ddfa0de455cfee6f2caa9f916fefdd233d7516))
* env example ([5774ccc](https://github.com/sleep3r/mtproto.zig/commit/5774ccc63d6c8019ecca54a1ea2cccd994ed976c))
* env example ([10b9722](https://github.com/sleep3r/mtproto.zig/commit/10b9722c63b7dec640121d62a592bb68c037617d))
* gemini md update anti dpi research ([b940bed](https://github.com/sleep3r/mtproto.zig/commit/b940bedb6b9ddabca22d605f52310221c1e5f10d))
* Initial ([bafd7e0](https://github.com/sleep3r/mtproto.zig/commit/bafd7e0481275998f486352dad8b499f9c6afbd4))
* Initial ([58aa01b](https://github.com/sleep3r/mtproto.zig/commit/58aa01b1aa4f0d9d29650333506fa50837b3297a))
* Initial ([a3cc105](https://github.com/sleep3r/mtproto.zig/commit/a3cc105992a6d83720f81bbb0910ab41648c15aa))
* Initial ([9481687](https://github.com/sleep3r/mtproto.zig/commit/9481687a1fba6c9ff902e9b8d921fe157d8d612d))
* Initial ([61c723e](https://github.com/sleep3r/mtproto.zig/commit/61c723e6e92768b54fb38673d2bab8bab6320aca))
* Initial ([ba009f3](https://github.com/sleep3r/mtproto.zig/commit/ba009f336c311b484a7206602120dfa7e14d94f5))
* Initial ([d32b49b](https://github.com/sleep3r/mtproto.zig/commit/d32b49b4858efec775e3e527123b8dabf1ac2fd0))
* Initial ([64f85ea](https://github.com/sleep3r/mtproto.zig/commit/64f85ea03d957a21131b0dfa82eae92607543bdd))
* Initial ([bd131ce](https://github.com/sleep3r/mtproto.zig/commit/bd131cedf0efddc75397d2b45dd4ecb88cb7c584))
* Initial ([7b1397b](https://github.com/sleep3r/mtproto.zig/commit/7b1397b4c26f551292d05b5b0a6e9fd15093775c))
* Initial ([3b951da](https://github.com/sleep3r/mtproto.zig/commit/3b951da407f8f1c2dde7ff0cfeaf24760f906f04))
* Initial ([eab15ed](https://github.com/sleep3r/mtproto.zig/commit/eab15ed30c0c2129e0c5b1dcb5ac9c35f450c7f9))
* Initial ([2298fb3](https://github.com/sleep3r/mtproto.zig/commit/2298fb3c8d0bcbc7327071b68ec2068094352fdf))
* Initial ([049d82e](https://github.com/sleep3r/mtproto.zig/commit/049d82e374ba5fa87e955557383fbe90c25aefb7))
* Initial ([4285955](https://github.com/sleep3r/mtproto.zig/commit/42859556d62aad06cf2179dfe0d60200f3d8799c))
* Initial ([2471da7](https://github.com/sleep3r/mtproto.zig/commit/2471da75ce55d5401c1de9710f971236357663d3))
* Initial ([e97fa99](https://github.com/sleep3r/mtproto.zig/commit/e97fa996d961277a0ac3be87f166a9d67a3f572a))
* Initial ([b76afda](https://github.com/sleep3r/mtproto.zig/commit/b76afda28a0a662c778d7cd62ee8e7979ac32f74))
* Initial ([6d55a6e](https://github.com/sleep3r/mtproto.zig/commit/6d55a6e78d8252b465e2e93b3b52f26f304d0ef8))
* Initial ([84cf8b3](https://github.com/sleep3r/mtproto.zig/commit/84cf8b34db3bb2dffdfa0325fe461b605f5acbc9))
* Initial ([b0b8e1e](https://github.com/sleep3r/mtproto.zig/commit/b0b8e1e1026e1524aaf91f1f879719d37a24d4fe))
* Initial ([074f16e](https://github.com/sleep3r/mtproto.zig/commit/074f16ec66bb6be48aee7d89bc9adb8f9c61a794))
* Initial ([5000a46](https://github.com/sleep3r/mtproto.zig/commit/5000a46008c45c988c9304668b0b2fb93a71209f))
* three-layer DPI bypass (\u0422\u0421\u041f\u0423 evasion) ([a6d7aae](https://github.com/sleep3r/mtproto.zig/commit/a6d7aae426e39030b975bede87980d620e3d3e4c))


### Bug Fixes

* apply TCPMSS DPI bypass rule to IPv6 out of the box via ip6tables ([17a58bd](https://github.com/sleep3r/mtproto.zig/commit/17a58bdde19ca2f62d934e114bac50eb88337b15))
* cache mask domain DNS at startup, prevent SEGFAULT on small-stack threads ([8653964](https://github.com/sleep3r/mtproto.zig/commit/8653964ce5eb26e027fdd6afe36d6fe3124ab34f))
* correct Zig tarball naming convention in install script (closes [#1](https://github.com/sleep3r/mtproto.zig/issues/1)) ([4affb92](https://github.com/sleep3r/mtproto.zig/commit/4affb923ce5e9a32a0eb6192c3363abd7c3214e9))
* **deploy:** add missing build dependencies for zapret nfqws ([f156511](https://github.com/sleep3r/mtproto.zig/commit/f156511ad2875ed56f996c5c3144bdb5c546de49))
* **deploy:** prevent apt-get update from crashing installation on third-party repo failures ([#4](https://github.com/sleep3r/mtproto.zig/issues/4)) ([51e4c18](https://github.com/sleep3r/mtproto.zig/commit/51e4c185b8f737d9e9c131ad9529c9360bb2f4eb))
* disable FAST_MODE for Media DCs to fix large channel images ([21f43bd](https://github.com/sleep3r/mtproto.zig/commit/21f43bd70b2e965a9058d445e832b2650710b551))
* install xxd in deploy script (closes [#13](https://github.com/sleep3r/mtproto.zig/issues/13)) ([b87872d](https://github.com/sleep3r/mtproto.zig/commit/b87872d569a2e12557a6f9f62523bb84627ea5b7))
* **middleproxy:** align promo ME routing and deployment sync ([fb285a2](https://github.com/sleep3r/mtproto.zig/commit/fb285a24e9577b644562dd822d840eff2e222f62))
* **middleproxy:** skip s2c noop padding frames ([f76998f](https://github.com/sleep3r/mtproto.zig/commit/f76998f047a48df3cc8092d0044e822e74647f1d))
* **middleproxy:** stabilize dc203 relay and refresh proxy metadata ([b8e2059](https://github.com/sleep3r/mtproto.zig/commit/b8e2059073833cb8e866712f39244f562b07704e))
* **proxy:** distinguish between native IPv6 and IPv4-mapped IPv6 in connection logs ([512be10](https://github.com/sleep3r/mtproto.zig/commit/512be100dff5ba2c6d19669c1aa5f850cd9cc196))
* **proxy:** panic in formatting invalid byte array on non-tls connections ([#6](https://github.com/sleep3r/mtproto.zig/issues/6)) ([13816d9](https://github.com/sleep3r/mtproto.zig/commit/13816d9bd4b20bdff42f816b12c57ce76a799c09))
* **proxy:** use std.fmt.bytesToHex for Zig 0.15 compatibility ([70df373](https://github.com/sleep3r/mtproto.zig/commit/70df37385b61cf6a90523ecb327e6008094cdeca))
* readExact WouldBlock handling for fragmented TCP, add iptables to install.sh ([0a33cbe](https://github.com/sleep3r/mtproto.zig/commit/0a33cbe0dda9d0f1bc36e003693bfa038a907b69))
* remove log_level=.debug override causing 93% CPU under load ([5d7d3c1](https://github.com/sleep3r/mtproto.zig/commit/5d7d3c1f3b46bff563e16ec40b9480eb218d6f27))
* workaround zig 0.15.2 cross-compilation bug in Makefile ([bbb6e22](https://github.com/sleep3r/mtproto.zig/commit/bbb6e220158f03aec0bc5346b54b9ee578980d0f)), closes [#2](https://github.com/sleep3r/mtproto.zig/issues/2)
