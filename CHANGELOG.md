# Changelog

## [1.0.0](https://github.com/atomicgravity/postern/compare/v0.15.3...v1.0.0) (2026-05-15)


### Miscellaneous

* release 1.0.0 ([956a897](https://github.com/atomicgravity/postern/commit/956a897d08d335449c61e7111edb02bfd8462ede))

## [0.15.3](https://github.com/atomicgravity/postern/compare/v0.15.2...v0.15.3) (2026-05-15)


### Bug Fixes

* **security:** close audit denial-of-audit DoS + scheme validation + OIDC sub-claim gaps ([167377f](https://github.com/atomicgravity/postern/commit/167377f9e4a625b38d74275c6b185fe583e27268))

## [0.15.2](https://github.com/atomicgravity/postern/compare/v0.15.1...v0.15.2) (2026-05-15)


### Documentation

* **audit:** 2026-05-15 five-lens audit reports + SUMMARY ([8362fe1](https://github.com/atomicgravity/postern/commit/8362fe16c115b6234ff6beb64b670084e9c2642b))
* sweep residual drift after tunneling-phase close ([504df9c](https://github.com/atomicgravity/postern/commit/504df9c2f639faedcf6a09d9f9dab357b4fc411e))
* **team-handoff:** record 2026-05-15 audit results + carry remaining items to backlog ([0743e25](https://github.com/atomicgravity/postern/commit/0743e25cb53536bf419b5471132c8afb53c1250d))

## [0.15.1](https://github.com/atomicgravity/postern/compare/v0.15.0...v0.15.1) (2026-05-15)


### Bug Fixes

* **broker:** timefix cert ValidAfter floor 1979-01-01 → 1970-01-01 (Unix epoch) ([d3d7d20](https://github.com/atomicgravity/postern/commit/d3d7d204ffc964b6f7b4bacc2a6aaad41e0562ae))


### Documentation

* **on-device/sshd:** timefix user needs /bin/sh, not nologin; cert window 1970–3000 ([e04a9b0](https://github.com/atomicgravity/postern/commit/e04a9b0b0afc3ec7cf8070489e5e3c9fddbb59c6))
* **readme:** engineer flow first, setup pieces (broker + device + laptop) below ([5dba185](https://github.com/atomicgravity/postern/commit/5dba18566299347f20baf6da124f218d8097e762))
* **readme:** position postern mint as the daily refresh action for vanilla-tooling flows ([363959a](https://github.com/atomicgravity/postern/commit/363959a77f0f5310d510f0234d3b37d6017c5f97))
* refresh README usage, sync DESIGN/AGENTS with landed tunneling + unified user resolution ([e3096b4](https://github.com/atomicgravity/postern/commit/e3096b4357fb95f832b91461d3a9302c7baa3045))
* update readme ([c99ce09](https://github.com/atomicgravity/postern/commit/c99ce096d6e542934e212ca5caf325ff75475040))

## [0.15.0](https://github.com/atomicgravity/postern/compare/v0.14.3...v0.15.0) (2026-05-15)


### ⚠ BREAKING CHANGES

* **tunnel:** engineers using `ssh widget-042` to reach a tunneled device need to switch to `ssh widget-042.tunnel`. The unwrapped path (`postern tunnel <device>` then `ssh <device>.tunnel`) replaces the prior shape (`postern tunnel <device>` then `ssh <device>` against the silently-overridden loopback block).

### Features

* **cli:** unify ssh user resolution across add-host, tunnel, ssh, scp ([219d006](https://github.com/atomicgravity/postern/commit/219d006fbb05819c01519a959164122eb421c28e))
* **mint:** warn when ~/.ssh/config lacks the Postern Include ([bd29804](https://github.com/atomicgravity/postern/commit/bd2980432b38eae5894d67d3fa1729a9e42466d3))
* **tunnel:** warn when ~/.ssh/config lacks the Postern Include ([332ecfb](https://github.com/atomicgravity/postern/commit/332ecfb48ee6c2b72f5f91be241528d7d3888e4b))
* **tunnel:** write ephemeral stanza at &lt;device&gt;.tunnel hostname ([3a77e03](https://github.com/atomicgravity/postern/commit/3a77e038a2748cd26f9a1be86fa045b67e3e6a90))


### Bug Fixes

* **securetunnel:** emit V1-shape messages so AWS Greengrass destination accepts ([b189178](https://github.com/atomicgravity/postern/commit/b1891786c2ac41f6293bd3b1e55d62a7fa27c3cf))
* **securetunnel:** evict prior streams on new TCP accept ([d3b3ca0](https://github.com/atomicgravity/postern/commit/d3b3ca0f44b1e6dde13d2e9ca8eb63e6a35f6711))


### Documentation

* **team-handoff:** track tunneling enhancement backlog ([d7827cf](https://github.com/atomicgravity/postern/commit/d7827cf960a58d68c5aff2468ea038836b75b6a9))

## [0.14.3](https://github.com/atomicgravity/postern/compare/v0.14.2...v0.14.3) (2026-05-15)


### Bug Fixes

* **terraform:** grant iot:OpenTunnel on Resource:* ([5582acb](https://github.com/atomicgravity/postern/commit/5582acb6aec7f69aa8419461769db70aae984447))

## [0.14.2](https://github.com/atomicgravity/postern/compare/v0.14.1...v0.14.2) (2026-05-14)


### Bug Fixes

* **broker:** log raw AWS error on tunneling backend failure ([a192653](https://github.com/atomicgravity/postern/commit/a192653899eb60a607d6b10097d425ae62e3805c))
* **terraform:** drop iot:ThingName condition on iot:OpenTunnel grant ([a7d95b2](https://github.com/atomicgravity/postern/commit/a7d95b2d5b5b88f5753f363fa67f0be5fd9778db))

## [0.14.1](https://github.com/atomicgravity/postern/compare/v0.14.0...v0.14.1) (2026-05-14)


### Bug Fixes

* **terraform:** force schema-before-policy via output depends_on ([f8d90d3](https://github.com/atomicgravity/postern/commit/f8d90d366f1c667b03755315504d6bd0425447aa))

## [0.14.0](https://github.com/atomicgravity/postern/compare/v0.13.1...v0.14.0) (2026-05-14)


### Features

* **cliapp:** default ssh destination to the device-id ([d4c4c5a](https://github.com/atomicgravity/postern/commit/d4c4c5a1b0ec199c20663a3277643dd45e9e5421))
* **timefix-set-clock:** -tags no_rtc compiles out the RTC ioctl ([1d4026f](https://github.com/atomicgravity/postern/commit/1d4026f77e577ffad09c377fd3e542d39fc77d06))


### Bug Fixes

* **cedar:** declare OpenTunnel action in schema + starter policy ([788be26](https://github.com/atomicgravity/postern/commit/788be2695868cd94ba19058eb191a3b8a3809c3b))


### Documentation

* **cliapp:** move ssh destination caveat from Short to Long ([bca6368](https://github.com/atomicgravity/postern/commit/bca6368660543584400b883e17461f8ed3250453))

## [0.13.1](https://github.com/atomicgravity/postern/compare/v0.13.0...v0.13.1) (2026-05-14)


### Bug Fixes

* **terraform:** use data.aws_region.current.region not .name ([d0feac6](https://github.com/atomicgravity/postern/commit/d0feac63380dc74c472cef352a660c7eff7d91bf))

## [0.13.0](https://github.com/atomicgravity/postern/compare/v0.12.0...v0.13.0) (2026-05-14)


### ⚠ BREAKING CHANGES

* **timefix-apply:** deps.SerialPath renamed to deps.PrincipalsPath; defaultSerialPath ("/proc/device-tree/serial-number") replaced with defaultPrincipalsPath ("/etc/ssh/authorized_principals/timefix"). Operators with a working principals-init don't need a change beyond redeploying the new verifier binary — the principals file the operator was already populating for sshd is now also the verifier's source.

### Features

* **timefix-apply:** source expected serial from authorized_principals ([4ac7e25](https://github.com/atomicgravity/postern/commit/4ac7e25a0d72e512876c8979730799f14ab3a42b))


### Bug Fixes

* **cliapp:** surface unexpected stdout from timefix verifier ([8f7084e](https://github.com/atomicgravity/postern/commit/8f7084e7a914b247a0db14cc1d6097e4691e3df5))

## [0.12.0](https://github.com/atomicgravity/postern/compare/v0.11.0...v0.12.0) (2026-05-14)


### ⚠ BREAKING CHANGES

* **tunneling:** removes `tunneling_thing_name_prefix` Terraform variable introduced one commit ago in TN-E. The new `tunneling_thing_name_format` subsumes it; operators on the default get the same IAM grant.

### Features

* **tunneling:** close TN-E — terraform IAM + integration test + phase-close ([9bc7090](https://github.com/atomicgravity/postern/commit/9bc7090d1f768745afa98c9c0d8396dc96ee2661))
* **tunneling:** make AWS IoT thing-name format operator-configurable ([cf4c58e](https://github.com/atomicgravity/postern/commit/cf4c58e4635ffa95ba712c4a61647204d8853731))

## [0.11.0](https://github.com/atomicgravity/postern/compare/v0.10.0...v0.11.0) (2026-05-14)


### Features

* **broker:** /ssh/time-payload endpoint + shared request preamble ([d25e80c](https://github.com/atomicgravity/postern/commit/d25e80c781083570bc3161d71602ac3c99907dfc))
* **broker:** land TN-A tunneling — /ssh/tunnel + SRP split ([e389b28](https://github.com/atomicgravity/postern/commit/e389b288e5e31b664ac55d50f994aed876daf2b3))
* **cliapp:** cert-only auth defaults, HostName in stanza, -v flag ([d9a4f0f](https://github.com/atomicgravity/postern/commit/d9a4f0fc33d62b675bdddb9d54e7c1d5e640832c))
* **cliapp:** land TN-C — postern ssh --tunnel CLI integration ([fea58f7](https://github.com/atomicgravity/postern/commit/fea58f7033eb585593c5c9c6311dbc91906bf184))
* **cliapp:** land TN-D — postern scp --tunnel CLI integration ([fb6b0c5](https://github.com/atomicgravity/postern/commit/fb6b0c5b6971ce05eb0667873b7e9c49ae0929c6))
* **cliapp:** land TN-F — raw-tunnel + add-host-mints + state-aware mint ([86d7c0a](https://github.com/atomicgravity/postern/commit/86d7c0a320dbff896aa092dcad2cfae4c0c9e5f2))
* **cliapp:** postern timefix subcommand + brokerclient time-payload call ([edc495b](https://github.com/atomicgravity/postern/commit/edc495b030e03e528bb60d2f5787cbee240ca7cd))
* **timefix-apply:** on-device JWS verifier with build-tag-gated test path ([f038658](https://github.com/atomicgravity/postern/commit/f038658ae69ffb4a1ac4ec150a6df8b22d30bc39))
* **timefix-set-clock:** privileged setter + on-device packaging sample ([2c2c2fd](https://github.com/atomicgravity/postern/commit/2c2c2fd0746293cb8122803d69e502bfa11989dd))
* **timefix:** phase close — cert-gen, --ip, two-line wire, go-jose, integration ([e5c0b5c](https://github.com/atomicgravity/postern/commit/e5c0b5c65b5467dd7709d741965cd67bf69a561b))
* **tunneling:** land TN-B pure-Go V3 source proxy ([687b836](https://github.com/atomicgravity/postern/commit/687b836935cdc4af4d325c320ea9878ebf1942eb))


### Bug Fixes

* apply 2026-05-13 audit Medium/Low items (corr, broker, qual, docs) ([5ac8a80](https://github.com/atomicgravity/postern/commit/5ac8a80c79dcd8c8c0a5c728cba983bcce2417a8))
* audit findings sweep before tunneling phase ([8eb0efd](https://github.com/atomicgravity/postern/commit/8eb0efdba2d8365d97d6a850ac4433efa84d731a))
* audit pass [#2](https://github.com/atomicgravity/postern/issues/2) follow-ups (F-HR2-M1/M2, F-QUAL2-M1, alg-pin reframe) ([2b4615b](https://github.com/atomicgravity/postern/commit/2b4615be32bd896a04cb0df8e373d8fc7c96a2eb))
* **security:** close F-SEC2-H1 + F-QUAL2-H1; audit pass [#2](https://github.com/atomicgravity/postern/issues/2) consolidated ([dbb1b5f](https://github.com/atomicgravity/postern/commit/dbb1b5fb2266fc968135653af645ec50195ece5b))


### Documentation

* **audit:** post-timefix 5-lens audit consolidated ([6868ce6](https://github.com/atomicgravity/postern/commit/6868ce6f06d9e28dec7e80fe4fecade1792bab08))
* doc updates ([ae6517f](https://github.com/atomicgravity/postern/commit/ae6517fc0b9e8f92be6efa601e60e3aaf3d80f2c))
* drop stale phase archives + 2026-05-13 audit + spike artifacts ([c106a53](https://github.com/atomicgravity/postern/commit/c106a539e394d484095acd42eb6204b00713009b))
* open timefix phase (spec locked, TF-A ready) ([9cad065](https://github.com/atomicgravity/postern/commit/9cad065e6619e6d8f983cbb5d70a170691b34a19))
* **timefix:** /usr/sbin paths, env-var build-tag, audit split, no-cache CLI ([2982608](https://github.com/atomicgravity/postern/commit/2982608ca20ed9f35a47ed01816055cb6332c543))
* **timefix:** rename SignRaw -&gt; SignTimePayload, add invariant S ([77c6cef](https://github.com/atomicgravity/postern/commit/77c6cef42d311e2bd490895668769ce7e8e30113))
* **timefix:** tighten LD-69 to build-tag-only env-var gating ([6320d54](https://github.com/atomicgravity/postern/commit/6320d54209f9e8a17b534e6a6c2efacc0c338ab1))
* **tunneling:** clarify type-vs-file split + library-first reminder ([2456d96](https://github.com/atomicgravity/postern/commit/2456d96764804d45c3036b02d183b5f671374147))
* **tunneling:** lock spec; resolve OQ-TN-1..5 ([1a1ef7a](https://github.com/atomicgravity/postern/commit/1a1ef7aeb220ba6ccc13ba9d10884dc49c576fcb))


### Code Refactoring

* **broker:** Go 1.22 method-routed handlers, drop registry drain ([2e66646](https://github.com/atomicgravity/postern/commit/2e666461880e2883647719be567abc101356a1c3))

## [0.10.0](https://github.com/atomicgravity/postern/compare/v0.9.0...v0.10.0) (2026-05-13)


### Features

* **terraform:** expose module_version output, auto-bumped by release-please ([95d3216](https://github.com/atomicgravity/postern/commit/95d3216106987db08fa49d084b954b32d5190b44))

## [0.9.0](https://github.com/atomicgravity/postern/compare/v0.8.0...v0.9.0) (2026-05-13)


### Features

* **broker:** every /ssh/cert request produces exactly one audit entry ([fecf344](https://github.com/atomicgravity/postern/commit/fecf3441e2a879ddf10b753faa488a9658572650))
* **broker:** rate-limit before registry; split audit into authorized/issued/denied ([072f318](https://github.com/atomicgravity/postern/commit/072f318b9ae48089d5bf08d97830609816b1abd2))
* **terraform:** opt-in APIGW JWT authorizer + always-on access logging ([c016dda](https://github.com/atomicgravity/postern/commit/c016ddaeb5b415cd7f7947deba7de6f2f9b4a6e8))


### Bug Fixes

* **broker:** reject cert-shaped public_key to prevent KMS Sign panic ([d73f46a](https://github.com/atomicgravity/postern/commit/d73f46a034f376c576118ab31d0c6b3ec93367d1))
* **deps:** bump go-jose to v4.1.4 (CVE-2025-27144) ([d30e98b](https://github.com/atomicgravity/postern/commit/d30e98bb06af6958cc18c3ac33608bbbfb98a78e))
* **terraform:** /healthz also requires JWT auth when authorizer is on ([f909c0b](https://github.com/atomicgravity/postern/commit/f909c0bfba7b6cfbfb9aba85dbcf0f897b476e7f))


### Documentation

* **audit:** land 2026-05-13 multi-lens audit findings + consolidated summary ([67a18d8](https://github.com/atomicgravity/postern/commit/67a18d840aa6acf247e4be49e7a75f905c047c65))
* record LD-62/63/64 and the 2026-05-13 audit triage outcome ([d514023](https://github.com/atomicgravity/postern/commit/d514023a5bf4b19e63c80bb75105e3e39d6c85d3))
* record LD-65 (strict audit-coverage invariant + final pipeline order) ([97596db](https://github.com/atomicgravity/postern/commit/97596db88b6a1075fdfde4e1f67d6a9b2bbbb585))
* refresh README + AGENTS + registry-http-api for current v1 state ([aa4e72d](https://github.com/atomicgravity/postern/commit/aa4e72dc19f69ac058f5fbed179826a077634baf))
* **terraform:** warn about AVP Cognito entity-ID pool-id-prefix gotcha ([adf5184](https://github.com/atomicgravity/postern/commit/adf5184e76585f9afeb1cf0a9947a588ae37e123))

## [0.8.0](https://github.com/atomicgravity/postern/compare/v0.7.0...v0.8.0) (2026-05-13)


### Features

* configurable registry HTTP timeout; bump default 5s→15s ([7b7c4a3](https://github.com/atomicgravity/postern/commit/7b7c4a3f5fd32759defad13d482bb9253f950a10))
* **terraform:** add avp_cognito_group_entity_type for Cedar group entities ([b034136](https://github.com/atomicgravity/postern/commit/b0341366c1dfd0b2a18f4d9288528f68a69a371e))


### Documentation

* **terraform:** add openssl DER→PEM step to KMS pubkey extraction ([7c8f80b](https://github.com/atomicgravity/postern/commit/7c8f80bde1beb69ff69cdea64a8f0510fc2ac6da))
* **terraform:** use direct byte-assembly for KMS Ed25519 pubkey extraction ([e96c2eb](https://github.com/atomicgravity/postern/commit/e96c2eb034a3225e9ba522507b8fa2a418ca5d43))

## [0.7.0](https://github.com/atomicgravity/postern/compare/v0.6.1...v0.7.0) (2026-05-13)


### Features

* pipe bool/int Registry attributes through to Cedar; AVP overrides ([e54827b](https://github.com/atomicgravity/postern/commit/e54827ba9bff5bc93243760714db179d0d099486))

## [0.6.1](https://github.com/atomicgravity/postern/compare/v0.6.0...v0.6.1) (2026-05-13)


### Bug Fixes

* **broker:** log unexpected ssh-cert-issuer errors instead of swallowing ([5b07c4b](https://github.com/atomicgravity/postern/commit/5b07c4b852d306b866af8432449028363b10c2b0))

## [0.6.0](https://github.com/atomicgravity/postern/compare/v0.5.0...v0.6.0) (2026-05-13)


### Features

* **terraform:** make registry backend selectable; add HTTP-registry vars ([d152ac4](https://github.com/atomicgravity/postern/commit/d152ac49abf388089c80a8b34ca6cbfba26fb892))


### Documentation

* realign DESIGN.md §Distribution with cosign keyless ([0dc0320](https://github.com/atomicgravity/postern/commit/0dc03209e4f64ae603b14f11accef2e6cd547604))

## [0.5.0](https://github.com/atomicgravity/postern/compare/v0.4.0...v0.5.0) (2026-05-13)


### Features

* bootstrap release pipeline ([03fe7a3](https://github.com/atomicgravity/postern/commit/03fe7a3bc149bc75405bee4b06b7d8a5db674c59))
* bootstrap release pipeline take 2 ([f906cf7](https://github.com/atomicgravity/postern/commit/f906cf7590fa550b17a9414602f787e8aca7b9df))


### Bug Fixes

* chain goreleaser inside release-please workflow ([858eebf](https://github.com/atomicgravity/postern/commit/858eebf701f79bb4b4adda8e6f1e2d153f3d604e))
* pin sigstore/cosign-installer to v4.1.2 (no v4 mover tag exists) ([04466ad](https://github.com/atomicgravity/postern/commit/04466adf27304ac28e7f74b21496750acdbaf51d))
* switch cosign signing to the new Sigstore bundle format ([120641c](https://github.com/atomicgravity/postern/commit/120641cfc81b96cb3c5695ef6437987f99a9a001))

## [0.4.0](https://github.com/atomicgravity/postern/compare/v0.3.0...v0.4.0) (2026-05-13)


### Features

* bootstrap release pipeline ([03fe7a3](https://github.com/atomicgravity/postern/commit/03fe7a3bc149bc75405bee4b06b7d8a5db674c59))
* bootstrap release pipeline take 2 ([f906cf7](https://github.com/atomicgravity/postern/commit/f906cf7590fa550b17a9414602f787e8aca7b9df))


### Bug Fixes

* chain goreleaser inside release-please workflow ([858eebf](https://github.com/atomicgravity/postern/commit/858eebf701f79bb4b4adda8e6f1e2d153f3d604e))
* pin sigstore/cosign-installer to v4.1.2 (no v4 mover tag exists) ([04466ad](https://github.com/atomicgravity/postern/commit/04466adf27304ac28e7f74b21496750acdbaf51d))

## [0.3.0](https://github.com/atomicgravity/postern/compare/v0.2.0...v0.3.0) (2026-05-13)


### Features

* bootstrap release pipeline take 2 ([f906cf7](https://github.com/atomicgravity/postern/commit/f906cf7590fa550b17a9414602f787e8aca7b9df))


### Bug Fixes

* chain goreleaser inside release-please workflow ([858eebf](https://github.com/atomicgravity/postern/commit/858eebf701f79bb4b4adda8e6f1e2d153f3d604e))

## [0.2.0](https://github.com/atomicgravity/postern/compare/v0.1.0...v0.2.0) (2026-05-13)


### Features

* bootstrap release pipeline ([03fe7a3](https://github.com/atomicgravity/postern/commit/03fe7a3bc149bc75405bee4b06b7d8a5db674c59))
