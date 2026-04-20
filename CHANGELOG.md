# Changelog

## [0.19.2](https://github.com/sleep3r/mtproto.zig/compare/v0.19.1...v0.19.2) (2026-04-20)


### Bug Fixes

* **constants:** correct bundled middle-proxy addresses to match getProxyConfig ([#199](https://github.com/sleep3r/mtproto.zig/issues/199)) ([20c5089](https://github.com/sleep3r/mtproto.zig/commit/20c508908a839bf42e3152d303f29e1309dbe417))

## [0.19.1](https://github.com/sleep3r/mtproto.zig/compare/v0.19.0...v0.19.1) (2026-04-20)


### Bug Fixes

* **proxy:** address critical review findings (data corruption, DoS, perf) ([#197](https://github.com/sleep3r/mtproto.zig/issues/197)) ([a6b6c80](https://github.com/sleep3r/mtproto.zig/commit/a6b6c80cd5a340eca74bcc5183df4a65724fcede))

## [0.19.0](https://github.com/sleep3r/mtproto.zig/compare/v0.18.0...v0.19.0) (2026-04-15)


### Features

* **dashboard:** show proxy version in header ([#191](https://github.com/sleep3r/mtproto.zig/issues/191)) ([99b5d7d](https://github.com/sleep3r/mtproto.zig/commit/99b5d7d19431ea3a859e3fa4ab8028009ccd2a72))

## [0.18.0](https://github.com/sleep3r/mtproto.zig/compare/v0.17.1...v0.18.0) (2026-04-15)


### Features

* **dashboard:** replace pip3 with uv for dependency management ([#189](https://github.com/sleep3r/mtproto.zig/issues/189)) ([83614bc](https://github.com/sleep3r/mtproto.zig/commit/83614bcf57ee78538de42b93f0733cd0b977231e)), closes [#185](https://github.com/sleep3r/mtproto.zig/issues/185)
* Metrics endpoint ([#179](https://github.com/sleep3r/mtproto.zig/issues/179)) ([6cc6674](https://github.com/sleep3r/mtproto.zig/commit/6cc6674c21d52916f6b6d8492772bb0af3845f71))

## [0.17.1](https://github.com/sleep3r/mtproto.zig/compare/v0.17.0...v0.17.1) (2026-04-13)


### Bug Fixes

* **dashboard:** detect dead tunnels as unhealthy ([#180](https://github.com/sleep3r/mtproto.zig/issues/180)) ([b6e6b8c](https://github.com/sleep3r/mtproto.zig/commit/b6e6b8cd3ee634bdf905ea6e0ca931a876b86996))

## [0.17.0](https://github.com/sleep3r/mtproto.zig/compare/v0.16.0...v0.17.0) (2026-04-13)


### Features

* mtbuddy enhancements and custom bind IP ([#177](https://github.com/sleep3r/mtproto.zig/issues/177)) ([8c6796f](https://github.com/sleep3r/mtproto.zig/commit/8c6796f69030557f422d2aa6480ab440db9e2432))

## [0.16.0](https://github.com/sleep3r/mtproto.zig/compare/v0.15.3...v0.16.0) (2026-04-11)


### Features

* **mtbuddy:** ask about MiddleProxy during install ([#174](https://github.com/sleep3r/mtproto.zig/issues/174)) ([6985478](https://github.com/sleep3r/mtproto.zig/commit/69854788f41f7bc2c429e00e26f3752677c0072c))

## [0.15.3](https://github.com/sleep3r/mtproto.zig/compare/v0.15.2...v0.15.3) (2026-04-11)


### Bug Fixes

* **docker:** build portable amd64 image to avoid invalid opcode ([#170](https://github.com/sleep3r/mtproto.zig/issues/170)) ([79f3e34](https://github.com/sleep3r/mtproto.zig/commit/79f3e342bfed117a9d3a5b9b7d016170342f2bb3))

## [0.15.2](https://github.com/sleep3r/mtproto.zig/compare/v0.15.1...v0.15.2) (2026-04-11)


### Bug Fixes

* **ci:** use valid Zig CLI args in release AES check ([#162](https://github.com/sleep3r/mtproto.zig/issues/162)) ([816f702](https://github.com/sleep3r/mtproto.zig/commit/816f70255bccf1ece4b4fe2132a10f08db4c4d49))
* **ctl:** remove legacy netns listen directives from nginx masking config ([#165](https://github.com/sleep3r/mtproto.zig/issues/165)) ([60af41c](https://github.com/sleep3r/mtproto.zig/commit/60af41c9b8c330f9d901b73eb6a689d88d19f7dc))

## [0.15.1](https://github.com/sleep3r/mtproto.zig/compare/v0.15.0...v0.15.1) (2026-04-10)


### Bug Fixes

* **proxy:** decouple tunnel routing from netns and add dashboard controls ([#160](https://github.com/sleep3r/mtproto.zig/issues/160)) ([95b5194](https://github.com/sleep3r/mtproto.zig/commit/95b5194c01a767208686de91dd8fb40befec8f8d))

## [0.15.0](https://github.com/sleep3r/mtproto.zig/compare/v0.14.8...v0.15.0) (2026-04-10)


### Features

* SOCKS5 & HTTP CONNECT upstream proxies, generic tunnel type ([#158](https://github.com/sleep3r/mtproto.zig/issues/158)) ([ef5bc9f](https://github.com/sleep3r/mtproto.zig/commit/ef5bc9f83bc3ac8db3b09f3919b24fdf0591458f))

## [0.14.8](https://github.com/sleep3r/mtproto.zig/compare/v0.14.7...v0.14.8) (2026-04-10)


### Bug Fixes

* **ctl:** unify install to use release artifacts instead of building from source ([#156](https://github.com/sleep3r/mtproto.zig/issues/156)) ([f15844b](https://github.com/sleep3r/mtproto.zig/commit/f15844b26f0c6230a84d3d1e75b6e7362f1b4002))

## [0.14.7](https://github.com/sleep3r/mtproto.zig/compare/v0.14.6...v0.14.7) (2026-04-10)


### Bug Fixes

* **main:** enforce fail-closed max_connections safety clamp ([#152](https://github.com/sleep3r/mtproto.zig/issues/152)) ([24ea08c](https://github.com/sleep3r/mtproto.zig/commit/24ea08cdd2ecd328056db82a7d973cdc4a0bce3f))

## [0.14.6](https://github.com/sleep3r/mtproto.zig/compare/v0.14.5...v0.14.6) (2026-04-10)


### Bug Fixes

* **ctl:** honor configured public IP in generated links ([#146](https://github.com/sleep3r/mtproto.zig/issues/146)) ([ce6463d](https://github.com/sleep3r/mtproto.zig/commit/ce6463d96752a415d3be6ca6df8bb408c0bfd26c))

## [0.14.5](https://github.com/sleep3r/mtproto.zig/compare/v0.14.4...v0.14.5) (2026-04-10)


### Bug Fixes

* **uninstall:** stop and disable proxy-monitor service ([#144](https://github.com/sleep3r/mtproto.zig/issues/144)) ([a84babf](https://github.com/sleep3r/mtproto.zig/commit/a84babf2c5b00331a8d4c8f10b1c02189cd882ac))

## [0.14.4](https://github.com/sleep3r/mtproto.zig/compare/v0.14.3...v0.14.4) (2026-04-10)


### Bug Fixes

* **tunnel:** tolerate AWG DNS lines in netns setup ([#136](https://github.com/sleep3r/mtproto.zig/issues/136)) ([c5748c4](https://github.com/sleep3r/mtproto.zig/commit/c5748c495ce5e13a5d3502056b3a237bfcc8cbea))

## [0.14.3](https://github.com/sleep3r/mtproto.zig/compare/v0.14.2...v0.14.3) (2026-04-10)


### Bug Fixes

* **mtbuddy:** print all user links and persist masking domain ([#134](https://github.com/sleep3r/mtproto.zig/issues/134)) ([c457e33](https://github.com/sleep3r/mtproto.zig/commit/c457e33a9bbb2d7ef1436288d0d46fa904040f57))

## [0.14.2](https://github.com/sleep3r/mtproto.zig/compare/v0.14.1...v0.14.2) (2026-04-10)


### Bug Fixes

* **bootstrap:** redirect ok/step output to stderr to avoid subshell capture pollution ([#131](https://github.com/sleep3r/mtproto.zig/issues/131)) ([da886d4](https://github.com/sleep3r/mtproto.zig/commit/da886d4fd3523de9da11531cfddb0b7b382a2091))

## [0.14.1](https://github.com/sleep3r/mtproto.zig/compare/v0.14.0...v0.14.1) (2026-04-10)


### Bug Fixes

* **bootstrap:** download mtbuddy binary instead of mtproto-proxy ([#128](https://github.com/sleep3r/mtproto.zig/issues/128)) ([f0d0658](https://github.com/sleep3r/mtproto.zig/commit/f0d065821cbcac6d28851a58da378949ba979e20))

## [0.14.0](https://github.com/sleep3r/mtproto.zig/compare/v0.13.0...v0.14.0) (2026-04-10)


### Features

* **proxy:** add --help and --version flags to mtproto-proxy ([#127](https://github.com/sleep3r/mtproto.zig/issues/127)) ([3026c42](https://github.com/sleep3r/mtproto.zig/commit/3026c428b340f5c15fc849b60eeb4e2dea31aff4))


### Bug Fixes

* **bootstrap:** align artifact names with CI output ([#124](https://github.com/sleep3r/mtproto.zig/issues/124)) ([d8ccf51](https://github.com/sleep3r/mtproto.zig/commit/d8ccf5144b6a311519665ef2a1debcc3e9b37f28))
* **bootstrap:** look up binary by artifact name inside archive ([#126](https://github.com/sleep3r/mtproto.zig/issues/126)) ([b271a5b](https://github.com/sleep3r/mtproto.zig/commit/b271a5b047e879186147ca672d15af9511b5cac9))

## [0.13.0](https://github.com/sleep3r/mtproto.zig/compare/v0.12.0...v0.13.0) (2026-04-10)


### Features

* **ctl:** add --config flag to install command ([#121](https://github.com/sleep3r/mtproto.zig/issues/121)) ([8300412](https://github.com/sleep3r/mtproto.zig/commit/830041273eeb6146f6d69bd97ccd17df66602efa))

## [0.12.0](https://github.com/sleep3r/mtproto.zig/compare/v0.11.0...v0.12.0) (2026-04-10)


### Features

* introduce buddy — native installer & control panel ([#116](https://github.com/sleep3r/mtproto.zig/issues/116)) ([519baa7](https://github.com/sleep3r/mtproto.zig/commit/519baa7aa9177530f8a2295a7d530b14862e9337))


### Bug Fixes

* **docs:** replace mp4 videos with gif for README compatibility ([#119](https://github.com/sleep3r/mtproto.zig/issues/119)) ([078ab9d](https://github.com/sleep3r/mtproto.zig/commit/078ab9d855f681efbf03330dfd075ee040be3948))
* **docs:** use absolute URLs for README video embeds ([#118](https://github.com/sleep3r/mtproto.zig/issues/118)) ([8a920f5](https://github.com/sleep3r/mtproto.zig/commit/8a920f584b7a9d02b730687f7b114db4224f545b))

## [0.11.0](https://github.com/sleep3r/mtproto.zig/compare/v0.10.0...v0.11.0) (2026-04-09)


### Features

* **monitor:** make host/port configurable and fix awg idle status ([#112](https://github.com/sleep3r/mtproto.zig/issues/112)) ([93fec36](https://github.com/sleep3r/mtproto.zig/commit/93fec36085a53518549eb4d06dd190fbb4336a08))

## [0.10.0](https://github.com/sleep3r/mtproto.zig/compare/v0.9.4...v0.10.0) (2026-04-08)


### Features

* **config:** add per-user MiddleProxy direct bypass ([#107](https://github.com/sleep3r/mtproto.zig/issues/107)) ([877b410](https://github.com/sleep3r/mtproto.zig/commit/877b410ebf20cdf5912968ba61ea61c5c054df12))


### Bug Fixes

* **proxy:** improve middle-proxy NAT detection for AWG tunnels ([#105](https://github.com/sleep3r/mtproto.zig/issues/105)) ([7b30617](https://github.com/sleep3r/mtproto.zig/commit/7b30617bb4b22776a0a8499aed65ac1ee2966ca0))

## [0.9.4](https://github.com/sleep3r/mtproto.zig/compare/v0.9.3...v0.9.4) (2026-04-08)


### Bug Fixes

* **deploy:** honor configured server port in helper scripts ([#101](https://github.com/sleep3r/mtproto.zig/issues/101)) ([#102](https://github.com/sleep3r/mtproto.zig/issues/102)) ([07b3b93](https://github.com/sleep3r/mtproto.zig/commit/07b3b93987f2b1906a60a9b904deff5816517317))

## [0.9.3](https://github.com/sleep3r/mtproto.zig/compare/v0.9.2...v0.9.3) (2026-04-08)


### Bug Fixes

* public IP in AmneziaWG tunnel mode ([#97](https://github.com/sleep3r/mtproto.zig/issues/97)) ([119705b](https://github.com/sleep3r/mtproto.zig/commit/119705b5d5dd5d01585ed5798c908c61aea15ff9))

## [0.9.2](https://github.com/sleep3r/mtproto.zig/compare/v0.9.1...v0.9.2) (2026-04-08)


### Bug Fixes

* **deploy:** preserve tunnel service and avoid incompatible release binaries ([#93](https://github.com/sleep3r/mtproto.zig/issues/93)) ([7164040](https://github.com/sleep3r/mtproto.zig/commit/716404031183e1f96bcae79e6cfc08b3d1201b9b))

## [0.9.1](https://github.com/sleep3r/mtproto.zig/compare/v0.9.0...v0.9.1) (2026-04-07)


### Bug Fixes

* **proxy:** harden relay security and reduce middleproxy memory ([#89](https://github.com/sleep3r/mtproto.zig/issues/89)) ([5b36c6d](https://github.com/sleep3r/mtproto.zig/commit/5b36c6dd5b1a3afb5fe76de090b8a1e3a6f6a241))

## [0.9.0](https://github.com/sleep3r/mtproto.zig/compare/v0.8.1...v0.9.0) (2026-04-07)


### Features

* lightweight monitoring dashboard ([#86](https://github.com/sleep3r/mtproto.zig/issues/86)) ([8a56fd8](https://github.com/sleep3r/mtproto.zig/commit/8a56fd86dcc6d05df501794e4697999d81abdf1e))

## [0.8.1](https://github.com/sleep3r/mtproto.zig/compare/v0.8.0...v0.8.1) (2026-04-07)


### Bug Fixes

* **proxy:** close slots on client hangup during upstream connect ([#84](https://github.com/sleep3r/mtproto.zig/issues/84)) ([353a9c4](https://github.com/sleep3r/mtproto.zig/commit/353a9c49c3c7f973e5f22326e926005913064c23))

## [0.8.0](https://github.com/sleep3r/mtproto.zig/compare/v0.7.1...v0.8.0) (2026-04-06)


### Features

* implement proxy resilience optimizations ([#81](https://github.com/sleep3r/mtproto.zig/issues/81)) ([71fb157](https://github.com/sleep3r/mtproto.zig/commit/71fb1577c26d4f53dd8ee34f5151481947141b19))

## [0.7.1](https://github.com/sleep3r/mtproto.zig/compare/v0.7.0...v0.7.1) (2026-04-06)


### Bug Fixes

* **proxy:** stabilize tunnel middleproxy and tune small-VPS defaults ([#78](https://github.com/sleep3r/mtproto.zig/issues/78)) ([5304be3](https://github.com/sleep3r/mtproto.zig/commit/5304be3c4defd9609707a0a934ff7eb26f778dd7))

## [0.7.0](https://github.com/sleep3r/mtproto.zig/compare/v0.6.2...v0.7.0) (2026-04-05)


### Features

* AmneziaWG tunnel deployment for blocked regions ([#74](https://github.com/sleep3r/mtproto.zig/issues/74)) ([ba0cffc](https://github.com/sleep3r/mtproto.zig/commit/ba0cffc4b5f8dafae8a06a3c017a78bce3c6a0d4))

## [0.6.2](https://github.com/sleep3r/mtproto.zig/compare/v0.6.1...v0.6.2) (2026-04-05)


### Bug Fixes

* **deploy:** ensure correct permissions on config and deploy dirs ([#72](https://github.com/sleep3r/mtproto.zig/issues/72)) ([1d3d4b2](https://github.com/sleep3r/mtproto.zig/commit/1d3d4b2e2bb7b159cb5f025384d188deec5ecae6))
* **proxy:** harden fd-quota handling and nofile defaults ([#71](https://github.com/sleep3r/mtproto.zig/issues/71)) ([cb2751a](https://github.com/sleep3r/mtproto.zig/commit/cb2751ad2d299ef9a74b4ecc5d7906bf995bcaa5))

## [0.6.1](https://github.com/sleep3r/mtproto.zig/compare/v0.6.0...v0.6.1) (2026-04-05)


### Bug Fixes

* **proxy:** prevent epoll spin on failed upstream connect ([#67](https://github.com/sleep3r/mtproto.zig/issues/67)) ([2ace562](https://github.com/sleep3r/mtproto.zig/commit/2ace562c71db43662476a6b2b817ca91174b217a))

## [0.6.0](https://github.com/sleep3r/mtproto.zig/compare/v0.5.1...v0.6.0) (2026-04-05)

Architectural rewrite: single-threaded Linux `epoll` event loop replaces the thread-per-connection model.

### Features

* **proxy:** epoll event loop with pre-allocated connection pool and non-blocking state machine ([#61](https://github.com/sleep3r/mtproto.zig/issues/61)) ([1833855](https://github.com/sleep3r/mtproto.zig/commit/1833855))
* **proxy:** slab-based `MessageQueue` buffer pooling with tiered block sizes (tiny/small/standard)
* **proxy:** on-demand heap allocation for idle connections — sub-1 MB baseline RSS
* **proxy:** `writev` scatter-gather I/O for zero-copy relay writes
* **proxy:** DRS (Dynamic Record Sizing) — TLS records ramp 1,369 → 16,384 bytes mimicking Chrome/Firefox
* **proxy:** Zero-RTT cloaking with local Nginx for active probe timing analysis defeat
* print startup capacity estimate for connection limits ([#58](https://github.com/sleep3r/mtproto.zig/issues/58)) ([6155609](https://github.com/sleep3r/mtproto.zig/commit/615560909b398a11d55d053647bb5a066a0590e9))
* IPv6 AAAA troubleshooting docs for iOS connect delays
* client behavior matrix skill for platform debugging

### Performance Improvements

* **memory:** 8.8 MB RSS at 2,000 active TLS-auth connections (~90% less than Go/Rust alternatives)
* **memory:** 49 MB RSS at 12,000 idle held sockets (1.5–2.5× less than C implementations)
* **binary:** 177 KB static binary, zero external dependencies

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
