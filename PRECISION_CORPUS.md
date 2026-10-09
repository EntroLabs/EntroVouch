# PRECISION CORPUS

The repositories the README's precision figures were measured on, each pinned to the commit that was audited. Clone a repository at its commit, run `python -m entrovouch.no_egress_auditor <dir>`, and read every distinct finding against one question: is what the finding says about that line true?

Sets 1 to 3 were measured with version 1.0.0 of this package and earlier. Sets 5 to 37 and 39 were measured with earlier builds of version 1.1.0, and sets 38 and 40 with 1.1.0 as first shipped. Sets 41 to 46 were measured on 2026-10-08 on later builds; each section says which tool was measured on the build that ships. Sets 1 to 4 were re-run on 1.1.0 as shipped: every false and either-way class recorded for them is gone. Set 4 was re-read in full (197 findings, none false); the findings of sets 1 to 3 have not been re-read line by line, so their figures stand as measured. The README's figures (sets 42, 43 and 45 for `no_egress_auditor`, 41 to 46 for `cbom`, 50 for `key_provenance`) were re-run on 1.1.1, on the repositories each set lists, and give the same findings.

## Set 1 (held out at version 1.0.0, 94.1%)

Twelve repositories were pinned; the README's set 1 scores ten of them (marshmallow, pyflakes, httpie, websockets, paramiko, itsdangerous, blinker, cachetools, tabulate, wheel).

| Repository | Commit |
|---|---|
| blinker | `c3364059663df1ddce32799d6b1922af89a345f6` |
| cachetools | `3c082c654c2804b9354e4b62dbd2994f1aac464d` |
| cli | `5b604c37c6c67e18e7c3e9aee6c88a8c22b98345` |
| isort | `9f905615631c545f5aea2516508109350d1d2f7d` |
| itsdangerous | `672971d66a2ef9f85151e53283113f33d642dabd` |
| marshmallow | `7f0792bd7a06f72e393ec866ac1e89e1502ccfe1` |
| paramiko | `142f593e40ad767c5e3556cbace66dc84589620c` |
| pyflakes | `bda5e1d1c355a12b12a89741db64e990a99a886d` |
| python-dotenv | `a00cb2eed0704cd6d2071b2004c37e95ccc86ee5` |
| python-tabulate | `268615a5c27dc40e5c22454c07b44d5c50410da0` |
| websockets | `7db6ba3ead2bcfa7c914a9dfdba313b82a64b5dd` |
| wheel | `b25c3c2ef5c789116b0545889aea68f5f65185a7` |

## Set 2 (held out at version 1.0.0, 95.1%)

| Repository | Commit |
|---|---|
| starlette | `63c5760d8a672cee96e1e523d84bfa1c77d9ee4c` |
| werkzeug | `f7e37f0bf510fa355fdac3e922cc2078916b021f` |
| h11 | `62c5068c971579d61fa1b55373390e12f25fd856` |
| gunicorn | `afc7d2fd5dd9f1de455b1be6c10044030c0adf8e` |
| fastapi | `c30032a1b68fb36c03fffe1856369d3824607c7c` |
| trio | `0480602b48eda20f10283e7ac04ed01848d7acff` |
| pip-tools | `28538e4385d270b8500cc5e2088294cf13456aee` |
| requests-oauthlib | `f33dac32bd065b835b34e7f0a48025700aae1e31` |
| yarl | `0bd174e12201aa1690d63e1e85e94c31ce54d5be` |
| apscheduler | `81e9fdcaac8d6c72f4318cb7ff393c913c7f9440` |

## Set 3 (held out at version 1.0.0, 95.0%)

| Repository | Commit |
|---|---|
| falcon | `755411d2921eaae494cc90b4cd4b1be6ca9f1ded` |
| bottle | `cbd569c447b3fd53f194cef9a306146ce6a07a59` |
| sanic | `5ffc7b3710838eaf016d2f9612a86a08626915e5` |
| dnspython | `72d3e6efa7e9b33305042df26b7c1916341d6240` |
| httplib2 | `ba9bf505cd899f522f2bb58ca608444adf49afc1` |
| toolbelt | `bcd5f7be229e14089052be7e3b527ebcea0ae7b8` |
| uvicorn | `528a3ac5031bf777ccd966d74db3034fe99fd69c` |
| aiofiles | `e8c2d131037ec52a8b1fa339cac774f79023c1d7` |
| pexpect | `fc8f062518b40bd0862aae870cdedf5d9c0c7fc3` |
| hypercorn | `0e2311f1ad2ae587aaa590f3824f59aa5dc0e770` |

## Tuning set (used to find and fix false-positive classes; no precision figure is quoted from it)

| Repository | Commit |
|---|---|
| arrow | `2224255c4acc594d734cef0bbc83360452a67983` |
| attrs | `8f767776326faaed11e6c2974798787f6e19b343` |
| click | `06b2a678741131fd577ce170e23e5ca0aeba0309` |
| dateutil | `2642afacc33fb839c404b75b230fff58b79793f2` |
| flask | `d73fa1cdcbd8b1465c151db8924ba58b1dd14e35` |
| httpx | `b5addb64f0161ff6bfe94c124ef76f6a1fba5254` |
| humanize | `392aef707c0e74341ab4a51420984e9ea6b566c5` |
| jinja | `5ef70112a1ff19c05324ff889dd30405b1002044` |
| markupsafe | `b2e4d9c7687be25695fffbe93a37622302b24fb1` |
| more-itertools | `790bb0bb2c03e7a07282e5f16f4b1fde35b8fcf5` |
| packaging | `7b898d9f0b343ca06993157fc328d7caad51d5c2` |
| pluggy | `012fd24a1f2fba6dba63641097e9f489f132bee7` |
| python-sortedcontainers | `3ac358631f58c1347f1d6d2d92784117db0f38ed` |
| pyyaml | `34a9bf82357f4952d8f194a5a31f1c39743652d0` |
| requests | `611c6162cbc4ac2020a2f91c7cfa4f3abf9bbb60` |
| rich | `9d8f9a372cc5916fd4781fec207ced7ddac2f08f` |
| tomli | `5a77b12a7a9f052ce5a20c335d2825658f6aea52` |
| toolz | `451af60dec590a6010e2babdbf391ea8f815122f` |
| tqdm | `9cf5a12b1f955468a17f0ba3c59092b23e4258ac` |
| urllib3 | `bcf84e6815f623521e1ffe3e6ab0224d778929c0` |

## Set 41 (all three tools, 2026-10-08; tuning data now)

Drawn on 2026-10-08 from the public repository search (language Python, 300 to 15,000 KB, pushed in 2026, created before 2022, not archived, not a fork), licence MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0 or ISC, never in an earlier set; the draw was made with a fixed seed and repositories were skipped, whatever they contained, when their owner is the author of a Meta-originated or a Chinese-origin project or when they are exploitation tools. Cloned shallow, read as text, never run.

| Repository | Commit |
|---|---|
| sripathikrishnan/redis-rdb-tools | `548b11ec3c81a603f5b321228d07a61a0b940159` |
| OWASP/Nettacker | `2bb5a52c70eaf2c185dc7097a78e46a09af2ef4e` |
| KaiyangZhou/deep-person-reid | `f8cd150fdf77e8d9e1ed143b7f308c2c609ded50` |
| davidhalter/jedi-vim | `a13c7bf64dbb4abcf676b4e41c5fedc2d4e7f6dd` |
| wkentaro/gdown | `e0734b3069b6e16bdd143a8544da280e15aae6ef` |
| aws-cloudformation/aws-cloudformation-templates | `a0f43bc6d20813052892546f445037cf84c75b54` |
| isso-comments/isso | `413d447a46437d0e9ccf206c8525119355e291d4` |
| gitpython-developers/GitPython | `1af7ce6e71d8bfaf4a4cc8f636d8df8b57463944` |
| pythonguis/pythonguis-examples | `cbcdc958ae8dc8baa135866c342063d9ceb98d32` |
| cloudtools/troposphere | `248b7fd6e0cac1636f72e72b4f9fc8874371f06c` |

`no_egress_auditor`: 780 findings; 3 false, 2 either way (99.62%; 99.36%). False: a list of package names in a pipeline step's input read as a command (1, left in); `pip install --no-deps` of a wheel in the working folder (1) and `npx --no-install` through a make variable (1), both fixed. Either way: a package beside a script named like a library it imports (1, left in), the word `npx` on the line that assigns it (1, left in).
`cbom`: 116 components; none false; 4 either way (a scanner's own list of cipher strings to probe with).
`key_provenance`: 232 findings; 194 false, 17 either way. 179 of the false findings are two classes: a cloud template's `Key` tag (112) and a translation table's labels (67). Both are fixed; the set is tuning data.

## Set 42 (all three tools, 2026-10-08; `no_egress_auditor` and `cbom` measured on the build that ships)

Drawn on 2026-10-08 from the public repository search (language Python, 300 to 15,000 KB, pushed in 2026, created before 2022, not archived, not a fork), licence MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0 or ISC, never in an earlier set; the draw was made with a fixed seed and repositories were skipped, whatever they contained, when their owner is the author of a Meta-originated or a Chinese-origin project or when they are exploitation tools. Cloned shallow, read as text, never run.

| Repository | Commit |
|---|---|
| MaartenGr/KeyBERT | `6ce2da222663f97530350f0e2260d022a7a8a20f` |
| ponyorm/pony | `07136c853b180a5987523877a471a90296a5e2d8` |
| andialbrecht/sqlparse | `60cdc649726bf1bc4f1b336050560b336da715ec` |
| jamalex/notion-py | `f31081edef26882298eb0c31cf023e810a2a9a09` |
| elliotgao2/toapi | `fae6ec5f4f6ffcbf341a91819107546e05056ddf` |
| astroautomata/PySR | `789ce7aaf967fea295c05beb0143ba56d5db85da` |
| rapidfuzz/RapidFuzz | `db6e504539a9c895180b266a06b36a32cb6029ee` |
| evhub/coconut | `bdf64a9e662471f1df1752122ea69d8808f4de42` |
| miso-belica/sumy | `7c418d95136137b208cc8f3ee6ab04bc3a63c6c2` |
| asottile/pyupgrade | `0d2a571d7b30c2648a0cded8f1b53dd55fa27d2c` |

`no_egress_auditor`: 386 findings; none false; 3 either way (an image tagged `:local`).
`cbom`: 23 components; none false.
`key_provenance`: 15 findings; 12 false (a field named `*_key` holding a plain lowercase word: `provider_key = "mysql"`, `child_list_key = "content"`). Fixed afterwards; the set is tuning data for `key_provenance`.

## Set 43 (all three tools, 2026-10-08; `no_egress_auditor` and `cbom` measured on the build that ships)

Drawn on 2026-10-08 from the public repository search (language Python, 300 to 15,000 KB, pushed in 2026, created before 2022, not archived, not a fork), licence MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0 or ISC, never in an earlier set; the draw was made with a fixed seed and repositories were skipped, whatever they contained, when their owner is the author of a Meta-originated or a Chinese-origin project or when they are exploitation tools. Cloned shallow, read as text, never run.

Nine repositories: a tenth failed to check out on Windows (a file name with a drive letter in it).

| Repository | Commit |
|---|---|
| ml-tooling/opyrator | `3f443f05b6b21f00685c2b9bba16cf080edf2385` |
| microsoft/restler-fuzzer | `6d984deedbc54aad957fa3da0c7e9e5df23a2aee` |
| basnijholt/adaptive-lighting | `283fec08ae7d34901d13c32e91fb001f92395fe7` |
| google-deepmind/dm-haiku | `5e13a6667200701e701090e1893421e074f442a2` |
| tfeldmann/organize | `36a54572488d89dc9279d79848ecc067b632f1a5` |
| bazelbuild/starlark | `c0af0ea03dc90d3bbc021394b693e6957cc15030` |
| corpnewt/ProperTree | `51ed53dbe3c96a81686ae1fc47f6d2a92f668159` |
| kayak/pypika | `5e800d83a0f0ae14210410c02fd97e51e2e3f1d5` |
| TylerYep/torchinfo | `f150266dbfe33e2d356b2563c61fd61313bcdcd5` |

`no_egress_auditor`: 254 findings when read, none false, none either way; 244 on the final build (a continued Dockerfile instruction with comment lines in it now reports once, as one without them does; the 10 removed were true findings).
`cbom`: 16 components; none false.
`key_provenance`: 50 findings; 46 false, 1 either way: a grammar's `"token": "Refreshable"` (40 of them in one repository's test files) and sentinel constants. Fixed afterwards; the set is tuning data for `key_provenance`.

## Set 44 (all three tools, 2026-10-08; tuning data now for `no_egress_auditor` and `key_provenance`; `cbom` measured on the build that ships)

Drawn on 2026-10-08 from the public repository search (language Python, 300 to 15,000 KB, pushed in 2026, created before 2022, not archived, not a fork), licence MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0 or ISC, never in an earlier set; the draw was made with a fixed seed and repositories were skipped, whatever they contained, when their owner is the author of a Meta-originated or a Chinese-origin project or when they are exploitation tools. Cloned shallow, read as text, never run.

| Repository | Commit |
|---|---|
| mytechnotalent/Python-For-Kids | `578df818d578d12ae1c1c56ab084e86fdf2d11e2` |
| strawberry-graphql/strawberry-django | `b598d1f048b2c694a009f43341b9200901455079` |
| python-social-auth/social-app-django | `49de2055e6c87a41ee9e5a9f6e9f5e7a8ea014b2` |
| frappe/frappe_docker | `ca1826c21f7fa5c5b0ace69fd2ab297585154a52` |
| ungoogled-software/ungoogled-chromium-windows | `989b4382364baaddb8b3180e1eb1030ca96a7273` |
| MrPowers/chispa | `81da95a52f4a563931c0822d35c8ee85a0b10f91` |
| toluaina/pgsync | `8650c99b7ed5ef8fade2229701a54b92b728ca66` |
| uriyyo/fastapi-pagination | `a365d7fbccb9c60e7181ae1db961894fd50b4858` |
| castorini/pyserini | `7ea7eca0040dc7fa09491eb3561c2b640d69dcd7` |
| jsonpath-ng/jsonpath-ng | `d909b790fab965992965eead9b2ee9cf050835a6` |

`cbom`: 54 components; none false.
`key_provenance`: 566 findings; 526 false, 8 either way: 516 of the false are one setting, `eval_key: dl19-passage`, a dataset identifier repeated across one repository's configuration files. Fixed afterwards. `no_egress_auditor`: 1,193 findings read by distinct claim (285), one site each for the large classes; 8 false, none either way: `redis-cli` given a variable as its command word (6) and a finding placed on the line after a comment inside a continued Dockerfile instruction (2). Both fixed afterwards; the set is tuning data.


## Set 45 (all three tools, 2026-10-08; measured on the build that ships, no change was made from it)

Drawn on 2026-10-08 from the public repository search (language Python, 300 to 12,000 KB, pushed in 2026, created before mid 2022, not archived, not a fork), licence MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0 or ISC, never in an earlier set; fixed seed; repositories skipped, whatever they contained, when their owner is the author of a Meta-originated or a Chinese-origin project or when they are exploitation tools. Cloned shallow, read as text, never run. One more repository failed to clone.

| Repository | Commit |
|---|---|
| kha-white/manga-ocr | `c333b5d36e88d539d6b040b4c4cf90ad5ecd4f69` |
| lepture/mistune | `a1b50bc12e066e5707ff797f821829bfcdab03b5` |
| pynamodb/PynamoDB | `833d7e2ecda1c8edd55dd672d54057d6d4df1be7` |
| sigma67/ytmusicapi | `4aeaf7d0aa48e3fb56eb229ec04593655acba091` |
| liiight/notifiers | `da28661f787a0a923588852a5f1ea54bd1a0b7f9` |
| Dineshkarthik/telegram_media_downloader | `859272a8111b6a9ac3b32376d68f34f6a9775fd6` |
| thewhiteh4t/FinalRecon | `b5db3a46921195bec643065c560e19741852957c` |
| keleshev/schema | `310a1239b62f500284ce3bd91b7dabf70467f23e` |
| philipperemy/keras-attention | `79a2db30e3f0ff2788f1cb12b5f279b746e50022` |
| nolar/kopf | `7850627dfff997fdd2f10f5948b66fc9267bbd16` |

`no_egress_auditor`: 255 findings (85 claims); none false; none either way.
`cbom`: 28 components; none false; 3 either way (comparisons with `ssl.CERT_NONE` that check a setting).
`key_provenance`: 30 findings; 12 false (an API's field names written as constants, 7; a pagination key passed to a call, 3; a variable named `watch_key` holding `shuffleId`, 2), 7 either way (a public key, an empty default, certificates). Not fixed: the set stays held out.

## Set 46 (all three tools, 2026-10-08; measured on the build that ships at the time, tuning data for `key_provenance` and `no_egress_auditor` afterwards)

Drawn on 2026-10-08 from the public repository search (language Python, 300 to 10,000 KB, pushed in 2026, created before 2023, not archived, not a fork), licence MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0 or ISC, never in an earlier set; fixed seed; repositories skipped, whatever they contained, when their owner is the author of a Meta-originated or a Chinese-origin project or when they are exploitation tools; one project of Meta-co-originated lineage was cloned and not scanned. Cloned shallow, read as text, never run.

| Repository | Commit |
|---|---|
| databricks/dbt-databricks | `4d837908954b1a86c52413001ddc86e70db62a59` |
| fabiocaccamo/python-fsutil | `c5dfadc15e28aa009273b8367ce7c644999572be` |
| MaxHalford/prince | `136d2aaef7323b8ccbb185859d4fec34af62979f` |
| dylanljones/pyrekordbox | `43137cb91f8297c768d2a8bdce5b27b2225f0a2d` |
| google/budoux | `1258a53418ca46a6706482a6d6abfff58e70a6eb` |
| django-json-api/django-rest-framework-json-api | `4e5136e5a866516e5719988558b636e589389cfb` |
| Chia-Network/pool-reference | `baf3067c816696eacf13c2ec13a2445a4639bdad` |
| elementary-data/dbt-data-reliability | `837e006fcb371c49d829aec77d5db69e3ce24608` |
| micheles/decorator | `fb40e8699e8c7eb38d3b2b3e8c03ee1b68b81453` |

`no_egress_auditor`: 402 findings (116 claims); 1 false (a parameter named `exec` called as `exec()`; recorded as 2 when read, the saved rows hold one, at one line), none either way. Fixed afterwards: the call is now reported as unresolved (`method-named-exec`), which is an either-way finding.
`cbom`: 12 components; none false.
`key_provenance`: 52 findings; 31 false (test fixtures held in strings of several lines 19; a tag, regular expression or column type in a `*_KEY` constant 7; a file path 3; a command substitution 1; a masked token 1), 0 either way. Fixed afterwards.

## Set 47 (`key_provenance` only, 2026-10-08; measured on an earlier build of 1.1.0; tuning data afterwards for one class)

Drawn on 2026-10-08 from the public repository search (language Python, 250 to 3,500 stars, 300 to 10,000 KB, pushed after 2026-04-01, created before 2023, not archived, not a fork; results page 4), licence MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0 or ISC, never in an earlier set; seed 20261008; repositories skipped, whatever they contained, when their owner is the author of a Meta-originated or a Chinese-origin project or when they are exploitation tools (one drawn repository, from a Chinese university lab, was set aside unread and replaced by the next in the sample). Cloned shallow, read as text, never run. The auditor and `cbom` were not run on this set.

| Repository | Commit |
|---|---|
| johannfaouzi/pyts | `26603c11e0c71cb8f0acc0ce4d3fd5f75a5226d8` |
| jazzband/django-push-notifications | `613e7e9448a5b0d9d49da86d8b5d4f5390e7cd85` |
| NyanNyanovich/nyan | `2d1c537dd8735230ed487194c1d063c70d6d995e` |
| google-deepmind/distrax | `10bf6ecd6409749b2dbdfe89eb4160cede868df2` |
| jeertmans/manim-slides | `df0f1f18f799cd38de0712b0abc4507d4d94b822` |
| alisaifee/limits | `0492c4fbef45c0f66c88c5feb00cb1270af238fa` |
| kishanrajput23/Jarvis-Desktop-Voice-Assistant | `e5c8840dd70e68446c974f562f5431cf4fe92cb0` |
| pyapp-kit/superqt | `2c25dbac6dd4bd93a99ea46208b72a59becada1a` |
| jjcremmers/PyFEM | `fff03df24398a093485683b9f6edb452be664ca3` |
| prometheus-pve/prometheus-pve-exporter | `cf3d659d27b598fa593ffe251065315210cbaf4a` |
| google/vizier | `4e3f61efa5cf43ea23e36ed2d94d97381c0ba090` |
| google/learned_optimization | `64f83138777cb923e4a83f6cf485b075037bf2bd` |

`key_provenance`: 13 findings, every one read at its source line. 9 true (a Django test `SECRET_KEY = "foobar"` in two settings files, 2; PEM private keys in a test-data folder, 2; private keys under `tests/tls/`, 4; a Google-API-key-shaped default in a template script, 1). 2 false (a dictionary mapping environment-variable names to configuration field names, `'PVE_PASSWORD': 'password'` and `'PVE_TOKEN_VALUE': 'token_value'`). 2 either way (a certificate in a file named `without_private.pem`; the placeholder `sk-or-...` in an example env file). 84.6% (69.2%). 7 of the 12 repositories gave no finding; two Python files in one repository (vizier) could not be parsed and are listed as such. Read by the author of the tool; a blind second reader later judged these findings together with set 48's (see below). The map from environment names to field names was fixed afterwards, so the set is tuning data.

## Set 48 (`key_provenance` only, 2026-10-08; measured on an earlier build of 1.1.0; tuning data afterwards)

Drawn on 2026-10-08 from the public repository search (language Python, 250 to 3,500 stars, 300 to 10,000 KB, pushed after 2026-04-01, created before 2023, not archived, not a fork; results page 5), licence MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0 or ISC, never in an earlier set; seed 20261009; repositories skipped, whatever they contained, when their owner is the author of a Meta-originated or a Chinese-origin project or when they are exploitation tools (one drawn repository, an exploit-search tool, was set aside unread and replaced by the next in the sample; one failed to clone). Cloned shallow, read as text, never run. Only `key_provenance` was run.

| Repository | Commit |
|---|---|
| Solvik/netbox-agent | `641bb97d14a1baed15a56553f0ca3f722042afc6` |
| JurajNyiri/HomeAssistant-Tapo-Control | `08d55dbdcbc38b980517be54c20b620eef3cdbe6` |
| br3ndonland/inboard | `819a7a91d1277882ca0094db4280781ceff99749` |
| google-deepmind/chex | `02bfaa78564cdcac0bf498f40d6e39edeebacd36` |
| conda/conda-pack | `405ace5fddab4d930cd65fd06602e61cf38880ec` |
| Mergifyio/daiquiri | `9dedafd1bc75c18d64a13e41d03db08d90bea046` |
| numba/llvmlite | `fac5ffe8ac216d419d1766019c162bee960edc97` |
| python-parsy/parsy | `fd4b015c76f2d7027f6f8ef1efbdaa23665ecfda` |
| PickNikRobotics/generate_parameter_library | `8c742e853ff776f6a4563a1cdabc266c3358e478` |
| m3dev/gokart | `c9d203087bf19586976cc3232d5872dd407145b7` |
| scikit-build/scikit-build-core | `92cb8a5f365c780aeb330b4f49cb6e5782af6ed7` |
| jannisborn/paperscraper | `76a36fb3103055ebeddfa4f35a453c41b5d69370` |

`key_provenance`: 16 findings, every one read at its source line. By the author: 2 true (a test fixture's default password `r4ndom_bUt_memorable`; a Codecov upload token in a workflow), 4 false (`"password": "Password"` in a framework's `strings.json`, 3; `redis_key='_SampleDummyTask_...-run'`, the name of a lock entry, 1), 10 either way (empty strings assigned to password names, 8; `test_token` and `test_key` in a test, 2). 75.0% (12.5%). A blind second reader called the 8 empty values false and agreed on the rest. 7 of 12 repositories gave no finding. All three false classes were fixed afterwards, so the set is tuning data.

## Set 49 (`key_provenance` only, 2026-10-08; measured on a build that already dropped empty values; tuning data afterwards)

Drawn on 2026-10-08 from the public repository search (language Python, 250 to 3,500 stars, 300 to 10,000 KB, pushed after 2026-04-01, created before 2023, not archived, not a fork; results page 6), licence MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0 or ISC, never in an earlier set; seed 20261010; repositories skipped, whatever they contained, when their owner is the author of a Meta-originated or a Chinese-origin project or when they are exploitation tools (one drawn repository, a tool that dumps data through leaked bot tokens, was set aside unread and replaced by the next in the sample). Cloned shallow, read as text, never run. Only `key_provenance` was run.

| Repository | Commit |
|---|---|
| pylast/pylast | `7c41ffe3d52ff79da989a0361334eef84bcfb0f1` |
| holoviz/param | `a45813bcda1340945c6a38e18f8c95114a2b4a95` |
| fl4p/batmon-ha | `5e32cdf651a90e914ceb51c37fc60a5a65672474` |
| datnguye/dbterd | `a2ce73de76306545cbff1e540f9d44db80ce1e78` |
| pbs/pycaption | `a9462a02febc9dd2d75ce41ad7c1723e75fc9b55` |
| abseil/abseil-py | `0918a3046ff49ef7eb03459693835ab9ce3458e6` |
| bieniu/ha-shellies-discovery | `8c9e8d4093aeb0fe971e7c75bbaf1ff314392ae3` |
| ArnesSI/netbox-inventory | `3b0765956a59b2563962a37963693b185506d227` |
| ebroecker/canmatrix | `12d801e2fd835e25676210e83b8c5f3deb82f9df` |
| xirixiz/homeassistant-afvalwijzer | `7211f9277df2ca62d2ed264c20427714597655e2` |
| ansible/event-driven-ansible | `7512a84083337d22e713f1c94492fa10a17cf729` |
| qdrant/qdrant-client | `cf747f4b6fa71ba35dfb467931f3fa65f2cdf263` |

`key_provenance`: 88 findings, every one read at its source line by the author and, separately, by a blind second reader given the findings, a few lines of context and the rule. Author: 13 true, 47 false, 28 either way (46.6%; 14.8%). Reader: 12 true, 47 false, 29 either way (46.6%; 13.6%). The two readings agree on 87 of 88 and on all 47 false findings (the one difference is a test configuration's `SECRET_KEY` made of the alphabet). The false findings: JSON-path test strings held in `jp_key` variables (27, one repository), the digest a test expects held in `hmac_digest` (8), the name of the field a vault input reads, `secret_key: "password"` (7), and five single findings (`seed='0'`, a URL path assigned to `token_endpoint`, field-name constants). Two repositories made 80 of the 88 findings; 5 of 12 gave none; one Python file in one repository could not be parsed and is listed as such. All four classes were fixed afterwards: the fixed build reports 43 findings on this set, and the 45 it no longer reports are the 45 the reader had called false, with none added. That is a figure on the set the fixes were made from, and not a measurement.

## Set 50 (`key_provenance` only, 2026-10-08; measured on 1.1.0 as published; held out, no change was made from it)

Drawn on 2026-10-08 from the public repository search (language Python, 250 to 3,500 stars, 300 to 10,000 KB, pushed after 2026-04-01, created before 2023, not archived, not a fork; results page 7), licence MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0 or ISC, never in an earlier set; seed 20261011; the owner and exploitation-tool exclusions of the sets above (none applied in this draw). Cloned shallow, read as text, never run; one drawn repository failed to clone, its leftover folder was moved out before scanning and the next in the sample taken. Only `key_provenance` was run, from a fresh clone of 1.1.0 as published, from a folder holding no `entrovouch/`.

| Repository | Commit |
|---|---|
| DenverCoder1/github-readme-youtube-cards | `a02c9b2b841c1cae3e8651571c0146a627423dc1` |
| sudoguy/tiktokpy | `19aff1a8a3137b3d7f284cc37253cb20ab88b2ac` |
| adamchainz/django-upgrade | `4077de1d0fafc80ee7c74a26a1147ca8fc2e95b1` |
| python-adaptive/adaptive | `b3a40ef04b28339c1edf2996455d1a7d685586da` |
| django-haystack/pysolr | `548fc7ac4d7637ad4351a15344d5c6bd0f0d9c57` |
| christiaangoossens/hass-oidc-auth | `ac2f69a8175a61e22353809870369bd560767867` |
| audiconnect/audi_connect_ha | `1ca3b82c4b95f9fc81d661107ebe44f02e64429e` |
| aio-libs/aiomonitor | `73de9b00b2b7671237120328b45c39374b0810d0` |
| pyvisa/pyvisa-py | `fbb29917988193bb801af23d4ba876e992a67b7e` |
| google-deepmind/mctx | `428bfb7e1c931715cd3d74f9c65e9991afd86df8` |
| nephila/djangocms-blog | `fcd965f85ea86ca7903704cfaaf972797c90546e` |
| microprediction/timemachines | `de094835d64a16445179a8537fade2b211d85dd5` |

`key_provenance`: 21 findings from 3 of the 12 repositories (9 gave none; no file was left unparsed). Each was read at its source line by the author, whose verdicts were written down first, and by a blind second reader (a separate model instance given only the findings, a few lines of context and the rule); **the two readings agree on all 21.** 2 true (`hs_secret = "top-secret-value"` and `secret = "top-secret-value"`, which two tests sign HS256 tokens with), 3 false (`CONF_CLIENT_SECRET = "client_secret"` and `CONF_REFRESH_TOKEN = "refresh_token"`, constants whose value is the name of the setting; `NESTED_DOC_KEY = "_childDocuments_"`, the name of a dictionary key), 16 either way (dummy tokens in mocked responses and test settings: `"access_token": "test-token"`, `"refresh_token": "idk-refresh-1"`, `"not-a-jwt"`, `DEMO_CLIENT_SECRET = "faz"`). **85.7% (9.5%)**; Wilson 95% intervals 65.4% to 95.0% and 2.7% to 28.9%. Not fixed: the set stays held out for this build.

## Set 38 (no_egress_auditor, held out at version 1.1.0 as shipped, 100%; 99.88% counting either-way claims as false; later builds were compared against it, so it is tuning data now)

| Repository | Commit |
|---|---|
| python-hyper/wsproto | `5e0685d0740ec30716897442f336de1118f5f40a` |
| Yakifo/amqtt | `6f9b35c1e7ff331cd8de2e6b05aa23dbecb39519` |
| 0rpc/zerorpc-python | `668af5b55c01e983cfa6c58b1c1db664460133a9` |
| Thriftpy/thriftpy2 | `f59e78b82a60afad2465d392b2f79bf5ca2ed3bc` |
| secynic/ipwhois | `b8c79c4e902467ccac0d841ad6ef820b1627e357` |
| python-mechanize/mechanize | `6545fbdc5bbc02d4846ddf1cf332ba619c8a2f95` |
| django/daphne | `d7a005258cce3ad7893a759274647f46331d782e` |
| geventhttpclient/geventhttpclient | `abb6f8b377b645f15283ca2fd774d9a06c808a12` |
| mymarilyn/clickhouse-driver | `b26f18bc01e1527b6e8759dbd40efd5fdc5787cd` |
| mixpanel/mixpanel-python | `091b0569eb5df69e9f5e9122bb763f92169d85e2` |

810 findings in 176 distinct claims on the build measured; 0 false; 1 either way: a broken address (`'"mqtt://someplace'`) handed to a
client's `connect` in a test that expects it to fail before connecting. Every call, command, listener, process and
markup site was read; the import and dependency kinds were read by module. Later builds read more of each tree and
add findings, every one read true, and drop none that was true: dependency declarations (in `pyproject.toml`,
tox.ini, a list `setup()` is given by name, and by distribution name), installs in pipeline files, base images
Dockerfiles declare, Compose images, `docker buildx build` and `docker compose up`, build tools and test runners
(`go mod download`, `go build`, `uv build`, `uv run`, `tox`, `python setup.py develop`), name lookups of a host held
in a variable, `openssl s_client -connect localhost` as `loopback-call` and `openssl s_server -accept` as
`inbound-listener`, and requirements a `setup.py` adds to its list as it runs (zerorpc-python's three `gevent`
lines, each read true), and `python -m build`, which installs its build requirements first (three lines, each
read true), and an example CGI script with a Python shebang that is Python 2 (mechanize's `echo.cgi`, reported
as not parsed, true). Measured on the build that ships: 867 findings, 0 false, 1 either way. The figure is
867 / 0 / 1.

## Set 40 (cbom and key_provenance, held out at version 1.1.0 as shipped; later builds were compared against it, so it is tuning data now)

| Repository | Commit |
|---|---|
| sigstore/sigstore-python | `dbe933f28eb6433d0271ab96e0f1349dc0912c8f` |
| theupdateframework/python-tuf | `1db152642ec023448a9dde7f199ddd63e920a108` |
| secure-systems-lab/securesystemslib | `15f35e9f2b611a9a9148814d5d2ba504c43f779e` |
| in-toto/in-toto | `e352b43ad7cb8915d84c36d791aa61346152a0a3` |
| dajiaji/pyseto | `628d6a34e0ede88abcb8234108272eda6745468d` |
| Yubico/yubikey-manager | `4ca60f706af930459138d8dc0f0f953480e1c7a4` |
| aws/aws-encryption-sdk-python | `a6c0413bb0ddc9bccdefad9f1d2c031e0bc4db29` |
| stef/pysodium | `27adf82a83d083ab8bb4a7b2388d3a067b307178` |
| GehirnInc/python-jwt | `81312b5b205f62252b3768f23157defe866937a8` |
| Legrandin/pycryptodome | `75cb955742c96f9b67325274c35e4f1cb13685c0` |

`cbom`: 4,188 components; 38 false; 2 either way = 99.09% (99.04%); without pycryptodome 2,292 / 9 / 0 = 99.61%.
The build that ships also reads Python scripts with no extension: python-tuf's `examples/client/client` and
`examples/uploader/uploader` add three SHA-256 uses, each read true. Reading `random.SystemRandom` as the operating
system's generator, a hash named to `hmac` by string, and a JWT decoded with `verify_signature` off replaces two
entries (yubikey-manager's and aws-encryption-sdk-python's `SystemRandom`, read true before and after) and adds
two, each read true (sigstore-python's unverified claims, yubikit's HMAC-SHA1). `hmac.compare_digest` compares two
values and computes no MAC, so it is no longer listed as HMAC: 14 entries leave (pyseto 10, python-jwt 2,
aws-encryption-sdk-python 1, yubikey-manager 1), each read true as a call of the `hmac` library before. A hash
named through a name bound once adds one entry, read true (python-tuf's `hashlib.new(_HASH_ALGORITHM)`, SHA-256),
and four `import hmac` lines of modules that use `hmac` only for `compare_digest` leave (read true as a library
before) while the hash a `pbkdf2_hmac` call names adds one (yubikit's SHA-1, read true), so the figure is
4,177 / 38 / 2 = 99.09% (99.04%), and without pycryptodome 2,281 / 9 / 0 = 99.61%. The OpenSSL name
`DES-EDE3-CBC` read as 3DES adds two entries in pycryptodome's PEM and PBES code, read true: **4,179 / 38 / 2 =
99.09% (99.04%)**; without pycryptodome unchanged.
False: an error message, a skip reason or a test-vector label naming an algorithm (38). Either way: an assertion
searching output for private-key armour (2).

`key_provenance`: 5,296 findings; 78 false; 548 either way = 98.53% (88.18%). pycryptodome supplies 4,787, nearly
all key test vectors that are true by construction (608 of them in one 1.3 MB HPKE vector file, read since the
size limit became 16 MiB); **without it, 509 / 78 / 86 = 84.68% (67.78%), the figure to quote.** Reading every
text file for private-key armour adds 4, private keys written in pyseto's README and documentation, true;
reading attribute and configuration-entry bindings adds aws-encryption-sdk's mock data keys (7 true, 4 wrapped,
either way), a GPG subkey ID (false, a listed class) and private JSON Web Keys in test fixtures (python-jwt 3,
pyseto 3; and 13 in pycryptodome's vectors), true. False: an identifier named with a key word (45), an encryption-context entry named `*_key` (23), a
secrets-manager reference in a build file (9), a keyring entry's default name (1). Either way: salts, public and
wrapped keys, empty defaults. These classes are left in. The 487 findings outside pycryptodome were judged again,
blind, by a second reader (an AI model given the same question and no first verdicts): 446 agreed; it ruled false
all 76 the first reading had ruled false and 2 more, of which the figures take one; the figures also take its verdict
where the first reading had counted an empty default or a public key true. The GPG subkey ID found since makes 78.

## Set 39 (cbom and key_provenance, measured on an earlier build of 1.1.0; tuning data now)

| Repository | Commit |
|---|---|
| pyca/pynacl | `d869c687681685c759f11142ec789b89fc62b56e` |
| Yubico/python-fido2 | `d1fd71182a7b677a34e15b8b221f272c9e72d77f` |
| jaraco/keyring | `7603e7cadc254b4c6e3fc2b2f0916a005e78087d` |
| IdentityPython/pysaml2 | `2fb5b50ad348e31f4847252c80261b89ccd9f053` |
| sybrenstuvel/python-rsa | `42b0e14ffbeeb9d99d1037e6440a2cc61780e4ea` |
| duo-labs/py_webauthn | `d72e0f53cb6684fdd2f178bae83aeab8bda64665` |
| vimalloc/flask-jwt-extended | `11785e00ea3e01b4eb57a8031843e215fe171c2a` |
| certbot/josepy | `7069e07e20408bf1bf911427f5d386a2d6471d5d` |
| python-trio/trustme | `ac8482fe98029a5c8566eb49ef1590b6af280e4d` |
| tlsfuzzer/python-ecdsa | `bff40c6cf2340148d410d5b3def0e949c547caf1` |

Chosen for the cryptography they hold. Read by the shape of the line and the primitive named, every PEM, prose and
library-level entry at its site.

`cbom`: 2,566 components; 99 false; 60 either way = 96.14% (93.80%). False: a PyNaCl helper, hash, password-hashing
or secret-key module labelled as the library's Curve25519/Ed25519 (84); an exception message or docstring naming an
algorithm (9); PEM armour that is a search string, an assertion or a docstring (6). Either way: PyNaCl imported as
a whole (57); benchmark code written in a string (3).

`key_provenance`: 243 findings; 67 false; 67 either way = 72.43% (44.86%). False: a pipeline cache key (23); an
option or attribute named with "key" (20); an identifier constant (a SAML URN named `PASSWORD`, an OID, a U2F key
handle, an HKDF info label, a mask) (13); the RFC 6979 HMAC key after it is mixed with the private key (6); PEM
armour that is a search string, an assertion or a docstring (5). Either way: salts in test vectors (44), empty
defaults (13), public keys (10). Handled in the build that ships: PyNaCl is classified by the module imported, a
message is not a use, and armour holds a key only with a body; key_provenance's names, URNs, OIDs, option
words, pipeline expressions and RFC 6979's reassigned key likewise.

## Set 38 for cbom and key_provenance (tuning data now)

The same ten repositories as set 38 above, read for `cbom` and `key_provenance` on an earlier build of 1.1.0:
`cbom` 181 components, 14 false, 22 either way; `key_provenance` 65 findings, 26 false, 5 either way. Their
classes (an algorithm named in prose or a test's name, `verify=` on a call that is not TLS, a pipeline secret
reference, names that only contain a key word, a value built from a variable) are handled in the build that ships.

## Set 37 (measured on an earlier build of 1.1.0, 99.61%; no either-way claims; tuning data now)

| Repository | Commit |
|---|---|
| codypiersall/pynng | `fb03025298dd40ea49fdeb0034ce6bfff055bce3` |
| dabeaz/curio | `c29701fbb8d0a7b8f28ea60639b36b75f5550366` |
| DataDog/datadogpy | `ce94a33d90e1c527cf269ff2a52ad9f0075215b2` |
| elastic/apm-agent-python | `faadc8e4d160422b115bd76c487c6b9356e118ce` |
| fsspec/gcsfs | `36766b5ff1cbf60f7315a8496b641b860ecd1a68` |
| fsspec/s3fs | `17a38ae9dc6ff4df64a338d69e26712c152a36ff` |
| jsocol/pystatsd | `08d04562d51fe8c8cf84144ba0ebfca5ad3c1e02` |
| kootenpv/yagmail | `4b61297e6ec2c32231254b2b32db73244c420e8c` |
| prometheus/client_python | `9cd073cb4dc6ee617eadf02dcdec94e0225eff0a` |
| python-lsp/python-lsp-server | `a3620069a607a63ed52569fde188e9301feae93a` |

779 findings; 3 false; 0 either way. False: a class method named `fetch` defined in a minified bundle (a math
typesetter's parser), read as a network call (2); a vocabulary identifier inside a template string,
`itemtype='https://schema.org/ListItem'` in a Hugo `printf`, reported as a link (1). Handled in the build that
ships: a method named `fetch` on an object claims less, and a vocabulary identifier is not where an anchor points.

## Set 36 (measured on an earlier build of 1.1.0, 99.72%; 98.45% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| confluentinc/confluent-kafka-python | `7f2e72f3db14647b163ee5fa7283d674eda194f3` |
| elastic/elasticsearch-dsl-py | `05fae5ea1b8edb05c42aae2b4160e42467b21432` |
| encode/requests-async | `1de1b948a09b1e164b62c3617b6702d266fc94b2` |
| googleapis/google-auth-library-python | `2ea24b03436765fa3cf279ce148482ff6332136b` |
| influxdata/influxdb-python | `bbe80ed32cf57b252be131d3edcda5ca610fc223` |
| MongoEngine/mongoengine | `3d4dfb840382f7873fd5ff70e79379c1b0e5b9d2` |
| psycopg/psycopg | `7b45cbc304e6a8a264f7dbc444a87cfae5b15064` |
| pytube/pytube | `a32fff39058a6f7e5e59ecd06a7467b71197ce35` |
| requests/requests-kerberos | `d4088c05ad7f3c1f4968590f3243404e50c36749` |
| Shopify/shopify_python_api | `a1597e953b1552c58c1cf8ad0bc481d594c90da5` |

709 findings; 2 false; 9 either way. False: an address whose host is this machine's own name, `http://$(hostname):8081`
in a test environment script, reported as an external URL (2). Either way: a real client method driven in tests with a
stub that answers for the network (`AuthorizedHttp(credentials, http=HttpStub(...)).urlopen(...)`, and a session whose
adapter's `send` is patched) (9). Fixed in the build that ships: this machine's own name (`$(hostname)`, `$HOSTNAME`)
is not an external address, and a fetch on a client built over a stand-in class the file defines, or inside a test that
patches a client class's `send`, is `network-target`.

## Set 35 (measured on an earlier build of 1.1.0, 98.88%; 98.33% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| celery/py-amqp | `d03ced39fd84280b8253330b165a22ad7a220c42` |
| encode/databases | `ae3fb16f40201d9ed0ed31bea31a289127169568` |
| eventlet/eventlet | `d0111a51ce7e9f035bd3a793219d0ba9a07cdba3` |
| irmen/Pyro5 | `9713d38151c522cefc15a9339cbae793cc7344b5` |
| jaraco/irc | `90e10e690da2c7bf60de21be4e36d24c9ffd7474` |
| linsomniac/python-memcached | `ae831510b6c9cacc4bcd8731d2f931eb611f362d` |
| MagicStack/uvloop | `07b10a433b60927e21518d1acfcc3b1a1b85f567` |
| scrapinghub/splash | `ab28b0233c245461189881f1f5656b96371a4b40` |
| Supervisor/supervisor | `abc60468ea4b78c446cf3a194f6fccb83d90f670` |
| tomerfiliba-org/rpyc | `08ad26b5e80cb1d6f1e1ef8ca2013e1b7ff293fb` |

717 findings; 8 false; 4 either way. False: an event loop's `sock_connect` or `sock_sendall` on a socket the same
function makes with `AF_UNIX`, reported as a network connection (7); `from urllib import unquote, splitquery`, Python 2's
string helpers, reported as a network import (1). Either way: the same calls on a socket whose family the file does not
show, in a file that also makes Unix sockets (4). Fixed in the build that ships: a Unix socket is a loopback call, a
socket whose family is not shown claims less, and a line importing only known pure names from the top of `urllib`
fetches nothing.

## Set 34 (measured on an earlier build of 1.1.0, 100%; no either-way claims; tuning data now)

| Repository | Commit |
|---|---|
| lextudio/pysmi | `5c6f4c6695232ef8f50b94047344994136ac557f` |
| requests/requests-ntlm | `717339ff800830e60fbd62294cb3033ee9a04a66` |
| vmagamedov/grpclib | `0d27158f98aa939493009e6844576d81ec7d8254` |
| inyutin/aiohttp_retry | `6f751ad61c07e1a958b04bb4ed690261ffae6f10` |
| aio-libs/aiodocker | `178d8a0fc9fa49dfb737d94f9e3be0f3d3ddce04` |
| pycontribs/jira | `bf7306b8b3905c91f97401eaae61d04827e1c309` |
| skshetry/webdav4 | `e656d7d04f7e7ce732dd743666a3cad3314293e1` |
| openstack/python-keystoneclient | `bd3d26799da905f72c97241bf57f9fa1943d174c` |
| mosquito/aiormq | `e79fda9ee51522742e0bf287d340c0a20d542fbb` |
| mosquito/aio-pika | `4f8b12497f4e4ec1df62b28a50fe1a479c5c10b8` |

563 findings; 0 false; 0 either way.

## Set 33 (measured on an earlier build of 1.1.0, 99.71%; no either-way claims; tuning data now)

| Repository | Commit |
|---|---|
| aiogram/aiogram | `b17c710ca9a05559e2141e1d16338b83dd50a445` |
| Vaelor/python-mattermost-driver | `8bbb99e0e744a5bb860b603ddf838ff3744d68bb` |
| lukecyca/pyzabbix | `f6c6ffe8e2e71de076f8e526bd9091146ca5c158` |
| cablehead/python-consul | `a91daae20c72625e764c10b5a98010df6b442238` |
| praw-dev/asyncpraw | `af8102bf9a457577b267efadf84ce35fc0b1bb5e` |
| PythonistaGuild/TwitchIO | `7340b19b100bcb263c43f751625b4488e5825872` |
| gawel/irc3 | `16875524a09c4487e36207b3ffe315392b8f8d21` |
| arangodb/python-arango | `c019d8643272db4621ffd7d20795a387618705a8` |
| neo4j/neo4j-python-driver | `f2c558f5ea24fa7f97d301c52582feb15e816e90` |
| PyMySQL/PyMySQL | `31126a3267e90134cd790d4f289a97ae108cf50c` |

342 findings; 1 false; 0 either way. False: a requirement installed from a `file:///` address, the project's own
folder, reported as a remote source (1). Fixed in the build that ships.

## Set 32 (measured on an earlier build of 1.1.0, 100%; 99.72% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| Anorov/PySocks | `c2fa43cbe1091e799e248e8e4433978916791a8b` |
| sschwarzer/ftputil | `97a5fc04b53e1e49093a1215df94357deadbf795` |
| pyrogram/pyrogram | `30de1e21e3e8b5949971ba0bba56bb818ba43b71` |
| matrix-nio/matrix-nio | `331c93ed3e9ca86e7444b4dfdf05086654842ace` |
| miguelgrinberg/simple-websocket | `4d1d45fe5cb9c45f3bfdc33968f0a1ab2c333d76` |
| wialon/gmqtt | `2513f1ffcc0b292e8ea4779b52545e138dd7f7a2` |
| frankie567/httpx-ws | `40ded286a1283639e871d2f6fe8c7d09723abdbd` |
| sonic182/aiosonic | `7a4ed8d95f7bdea2d0aa0352bd2c3f0370cc8174` |
| jawah/niquests | `fd4cf2a3e46e28e2765433da9a3c02a3e6e1f629` |
| pogzyb/asyncwhois | `979ea425c00428d962050bf154280c1d680d8751` |

351 findings; 0 false; 1 either way: a request to this machine's address routed through a named proxy, reported
as a loopback call (1). Fixed in the build that ships: a request to this machine routed through a proxy that is not
this machine is no longer a loopback call. matrix-nio was read from a `git archive` of its commit with one
test-data file skipped (`tests/data/encryption/@example:localhost_...db`): its name holds a colon, which a Windows
checkout cannot write.

## Set 31 (measured on an earlier build of 1.1.0, 99.80%; 99.60% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| pyserial/pyserial | `a5c48d445fbc1943d4fabf8d9090a50fda3172fd` |
| miketeo/pysmb | `0c7ab246945e4c5785b15400c9c08673b9541305` |
| pyvisa/pyvisa | `843d62a50cac9a23e7585c5135f3fd5eb9470f17` |
| KimiNewt/pyshark | `91441d3eee47e50e552ac2436df2ec89abad07b0` |
| cf-natali/ntplib | `6a0abf7b72b4691182d6b93792ef32d6f6b29f22` |
| elceef/dnstwist | `341395377f40761fe4152f43fd18eea757b6069a` |
| sshuttle/sshuttle | `fecd455fb291d7a51df956c83cb0feaa11ca9770` |
| Lawouach/WebSocket-for-Python | `21dc60e632b346b0575f17ae2cb5a1263df4a4df` |
| msoulier/tftpy | `a422daa8cc1dc64bb584dc545e3a3cb3fe40b0a9` |
| soimort/you-get | `049548f3f3f35e67ba8d3181c71fdc71d11cf260` |

498 findings; 1 false; 1 either way. False: a request object built and sent in one expression,
`urlopen(Request("https://..."))`, reported only as building a request (1). Either way: an address whose host is set
at run time (`http://$host:$port/` in a test script) reported as an external URL (1). Fixed in the build that ships: a
request built from a URL literal and sent in the same expression is a network call; an address whose host is a bare
name or a variable claims less.

## Set 30 (measured on an earlier build of 1.1.0, 99.45%; 99.31% counting either-way claims as false; 98.83% and 98.53% without pyatv; tuning data now)

| Repository | Commit |
|---|---|
| FreeOpcUa/opcua-asyncio | `bacc2db8f3e277f69be7c4ff7e7f058a9396ce62` |
| postlund/pyatv | `b277a4c8222ecdcbaab8a24e3e713ca44765adb4` |
| python-kasa/python-kasa | `ff261878e0241591cb623f894c1b0e7f462c9983` |
| esphome/aioesphomeapi | `26451b45fff576283826fd326845e5108f8ea296` |
| zigpy/zigpy | `fb63170d520e42c77ecd73e9dfc3061f980fc20d` |
| hbldh/bleak | `c7ca1b04b00b0bda5f98ccf9493e24784cfe869d` |
| home-assistant-libs/pychromecast | `17155d8a5582aa9405bb4359e6ec7b116c92461a` |
| SoCo/SoCo | `18effdc21312fa6e9a3c87e01741632275c3b481` |
| pywemo/pywemo | `0eb2fd991f4b0948051c21c94db1c040bd897879` |
| hardbyte/python-can | `b4f82abede25ff83376be793a2935c41f81c3869` |

721 findings; 4 false; 1 either way. False: shell commands written as text inside the JavaScript of an
`actions/github-script` step (3); a string appended to a shell array read as running wget (1). Either way: a connection
to a listener the same test bound to `127.0.0.1`, with no literal address on the line (1). Fixed in the build that ships: an `actions/github-script` block is
JavaScript, a shell array holds words, a socket bound to this machine is traced to the call given its address.

## Set 29 (measured on an earlier build of 1.1.0, 98.87%; 95.75% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| aio-libs/aiokafka | `13a6400024621371254f32e17bd489313dbcc63f` |
| aiortc/aiortc | `8a2864630bf417d977a06dda8d0254b1c1501bfb` |
| suds-community/suds | `fae24d440cd9357070ab56748b3774b2b4bbf21c` |
| python-ldap/python-ldap | `139b7c4ea10aa7d23f82420e50ba10696a5adaa0` |
| pyradius/pyrad | `6d9b0266955f25a09aae66586d0fe9a7cb593019` |
| kbandla/dpkt | `4f8958eb4b375b38d0ab6ffadf2da9b24395394d` |
| empicano/aiomqtt | `4c362b39a54a64e9a39720d29190cd56f98cb0ca` |
| romis2012/aiohttp-socks | `114a39c7f31f800abe2844cdd7333f9ac25f8d20` |
| abhinavsingh/proxy.py | `fec682bc7d702a934eafcf8ad6f1fba835ebef91` |
| novnc/websockify | `3dd228b81ade1ff76a27ad12eed6e78df8c6f8a6` |

353 findings; 4 false; 11 either way. False: NSS `certutil -d <db>` read as Windows certutil downloading (3);
`SysLogHandler(address='/dev/log')` called a network call (1). Either way: Cython source called compiled (8); a shell
variable holding a curl command (3). Fixed in the build that ships: certutil by its verb, a syslog handler by its
address, Cython named as source, a variable that holds a command reported as a word.

## Set 28 (measured on an earlier build of 1.1.0, 100%; 98.74% counting either-way claims as false; 100% and 98.56% without autobahn-python; tuning data now)

| Repository | Commit |
|---|---|
| geopy/geopy | `402cbba8b093e5e3f89c81b902f576d65608a123` |
| instaloader/instaloader | `7efc78de12e02feb1794b71125a48e66250f0db0` |
| Mic92/python-mpd2 | `ae4f8efbdc9e80613743c09430e7b7b8eccbc733` |
| napalm-automation/napalm | `820a06b2069eb1d7b0cbe8943ee2dea6e2949d1a` |
| nornir-automation/nornir | `9d15e93103bdb563d33a599c2eb8c50c1739787c` |
| bamthomas/aioimaplib | `5c1da0be493d336f0d54d3407b8bdcf7fd20a296` |
| crossbario/autobahn-python | `ca1e60c7f7dd78dc2df98a3b7bdc274ae197ae9c` |
| lextudio/pysnmp | `0a85a360745710cac00eb85f6b2296c896d5bbd7` |
| sammchardy/python-binance | `7d7b7fb029631db74852b2e84ed237911307495f` |
| csparpa/pyowm | `01efe4418edbd0a1a62f906037d10780b03712bb` |

952 findings; 0 false; 12 either way. Either way: a network call given a loopback address (an asyncio connection to
`"127.0.0.1"`, a page's WebSocket to `ws://127.0.0.1:9000`) reported as a network call (8); a project's real
connection method driven in tests with a plugin that connects nowhere (4). Fixed in the build that ships: the
loopback address (the event loop's second argument, a page's written-out WebSocket or fetch address), then the plugin
class (`unresolved-call` when the same file defines and registers the plugin).

## Set 27 (measured on an earlier build of 1.1.0, 93.54%; 92.21% counting either-way claims as false; 100% without elasticsearch-py; tuning data now)

| Repository | Commit |
|---|---|
| Rapptz/discord.py | `65232c38702be5844cf2ce865a4777eb1928b5d0` |
| eternnoir/pyTelegramBotAPI | `115464bc7188218d74e37ea565844fb1e5effb9e` |
| elastic/elasticsearch-py | `1c9b51fc270c6b0bebca45fb1a51f6c24489f0ba` |
| achillean/shodan-python | `87a0688d1e5b7e4bb13ae4f5fd7cb937a671cba8` |
| spyoungtech/grequests | `60f70e99e942a2df378b4e4f6202dcf862754c2d` |
| pycurl/pycurl | `e16f4f42e06dfc57726cfb23454c7c50b4738030` |
| saghul/aiodns | `8447e621d3cc976793d1a1576f701e536e4d4999` |
| python-trio/trio-websocket | `e828e54cfcfe425d53688aac7acd14dd695560a5` |
| jasonrbriggs/stomp.py | `71e7df2cc233f403a68978f0b98bd170a2006918` |
| carlmontanari/scrapli | `6b28155b1add174f8837491dcdaca0beb9fb9462` |

526 findings; 34 false; 7 either way. False, all in elasticsearch-py: the project's own
`connections.create_connection(hosts=...)`, which builds a client and connects nothing, reported as a network
connection (27); a shell `case` pattern `https://*)` reported as an external URL (3); prompt text in a YAML value
read as script lines (4). Either way: an address naming another container or compose service (6); a URL pattern
handed to a server's configuration (1). Fixed in the build that ships: the project's own method reached by an
absolute import (and on a generic class), a glob host in a script, text in a YAML value whose key names no script.

## Set 26 (measured on an earlier build of 1.1.0, 99.03%; 81.62% counting either-way claims as false; 99.10% and 98.51% without HTTPretty; tuning data now)

| Repository | Commit |
|---|---|
| mjs/imapclient | `fe29bad7279ceae97c382e2d966392dcc2620901` |
| paulc/dnslib | `e266b75fab4464350346200638dbd08c254b5b01` |
| alexdlaird/pyngrok | `30c4f4681f14bae416939adfd7961a2470bcebbb` |
| gabrielfalcao/HTTPretty | `f9f012711597634d40066d144a36888b3addcc46` |
| SvenskaSpel/locust-plugins | `d16a309780735dafc488f9ec37eafd4127445a4d` |
| SpamScope/mail-parser | `798712ce46d65d5d0a49232948b3e6a146f172b0` |
| seveas/python-hpilo | `668fe3acd5adece5a23d3abceee82e182b4024c8` |
| svinota/pyroute2 | `4b0b073df53a316f0bc12f79d85fec2077a31927` |
| aiortc/aioquic | `6d36838d008c2202c337142fa07e8bf80e96bac8` |
| richardpenman/whois | `3c050db870982d4f571420dedae25a122a30aec5` |

517 findings; 5 false; 90 either way. False: an `httplib2` request sent with a `body=`, worded as a test double's
registration (2); `create_datagram_endpoint(sock=...)` on a netlink socket worded as a network connection (1); two
text files named for the domain `sapo.pt` reported as serialised content (2). Either way: calls given a URL literal
inside HTTPretty's own tests, which activate httpretty and so replace the socket (88); `create_connection(sock=...)`
attached to a socket made elsewhere (1); `pip install` inside a Make `define` block (1). Without HTTPretty: 335
findings, 3 false, 2 either way. Fixed in the build that ships: a request's own `body=` on a traced client, a
connection given `sock=` (unresolved unless the file builds an internet socket), a text file named like an artifact
type, calls under httpretty or mocket (which now name the double), Make variables in conditionals and `define` blocks.

## Set 25 (measured on an earlier build of 1.1.0, 99.49%; 99.24% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| romis2012/python-socks | `b3259cf21a26a95081788ededf30a958b49d6ab4` |
| cole/aiosmtplib | `8df1fb228804e8dffa9d303c4a96d6c5848abfd9` |
| hikari-py/hikari | `4984ce88fc8a434cdb9bdf0f43c8fd18f7565af7` |
| netaddr/netaddr | `d340feab548d948c5dc92cedcb05c69f57f9386e` |
| ncclient/ncclient | `937ce511474634826ee085e61412354aff4565bb` |
| diyan/pywinrm | `cbc1e3475a516e2dabfc58925ed2bcd932856ccb` |
| vmware/pyvmomi | `75a18fde3089b66dc4c41c1d20fbc00acebe8e36` |
| tableau/server-client-python | `6b2bd09484231d9322136453ffec05ecf22cacc9` |
| pycontribs/jenkinsapi | `dda58f4e4efb143cd0c70f4ad4ee46a41b514337` |
| poezio/slixmpp | `7a0fb970833c778ed50dcb49c5b7b4043d57b1e5` |

395 findings; 2 false; 1 either way. False: release-note text whose escaped backticks are read as a command
substitution (1); a handler imported from `SimpleHTTPServer` reported as a listener (1). Either way: a Dockerfile
`RUN` that writes a script containing `curl` against this machine (1). Fixed in the build that ships: escaped
backticks are text, and the Python 2 server modules follow the handler rule; the `echo`-written script is reported
as a word, not a command run here.

## Set 24 (measured on an earlier build of 1.1.0, 99.72%; 98.58% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| MagicStack/asyncpg | `2c3750179e0289b2fd03dc2baa8e87f75afa174b` |
| aio-libs/aiomysql | `1aa9cfcbad60f14f5a8bdccaa660f10f69123015` |
| mongodb/motor | `3a9cd0dbe7c92d9d94e4b88707ec27c80093a88e` |
| marcospereirampj/python-keycloak | `c5848e806d8539e5e80d01d265e230ac870572f7` |
| caronc/apprise | `8d5ba19e885bc6096e55eeedfeefc84f2c2e2d98` |
| apache/libcloud | `8d659f527f28c76db41f19c86d056a2338717b8c` |
| sigmavirus24/github3.py | `9eeac0ddb241bf3099a6c904411e3aa23b62fd0d` |
| vsajip/python-gnupg | `d57332dbe3dec9454066bbb41a7127275c75d052` |
| olucurious/PyFCM | `5d1b95affcdea46b0ac38e2095c4d4290221569a` |
| redis/redis-om-python | `6fe4ecb0c7c7688dbb90fd383417c38611ed436f` |

1,054 findings; 3 false; 12 either way. False: `rsync` between two local directories reported as reaching the
network (2); `command -v curl` read as running curl (1). Either way: `$SUDO apt-get ...`, run behind a variable
used as a wrapper, reported as not shown to run (5); a real connection method called in tests that patch the
socket (7). Fixed in the build that ships: the local copy, the name lookup and the variable wrapper; calls
inside a `with` that patches the socket (6 of the 7) say nothing reaches the network.

## Set 23 (measured on an earlier build of 1.1.0, 99.34%; 98.75% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| aio-libs/aiobotocore | `3463973f1854342897c4a6e4ed0dc2bebeb0e9e1` |
| dpkp/kafka-python | `cd3f7938e1c119fa1e78c333778767606c2a802f` |
| nats-io/nats.py | `5cc8abbd9776472bf3438107970d98a208a4b400` |
| zeromq/pyzmq | `c6bc8f20d47f9e779d17137201939a31fcd457cc` |
| influxdata/influxdb-client-python | `7ed4ecf3fe502999790449d26b82bf142a8676d8` |
| opensearch-project/opensearch-py | `f09f8b04e82191e911c7a1097e338036d089cc6d` |
| aws/aws-xray-sdk-python | `48b6a8f2bb134c84b283666d1c2b4c1e9e6def6f` |
| jupyter-server/jupyter_server | `f8169d721a0e0abb9ca27266c83db5a3a09e29d7` |
| pymodbus-dev/pymodbus | `f05fa39965a2d9441fd345271710db092199cc0e` |
| googleapis/python-storage | `ab4997ce0f7b85947e84b226bd0edf6d714a946a` |

1,361 findings; 9 false; 8 either way. False: opensearch-py's `Connections.create_connection`,
which constructs and registers a client, reported as a connection (6); `websocket.create_connection` described as an
asyncio connection (1); a remote git subcommand named inside a quoted `grep` pattern in a workflow, read as a command after the
pattern's `|` (1); `pip install` in release-notes text piped by a heredoc into `gh release create` (1). Either way:
kafka-python's real proxy `create_connection` in a test with the network stubbed (7); a Makefile variable holding a
`docker-machine scp` command (1). Fixed in the build that ships: the quoted pattern, the release notes and the
websocket wording, then the `create_connection` that builds a client (judged as the project's own method). Left
in: both either-way classes.

## Set 22 (measured on an earlier build of 1.1.0, 99.93%; 99.69% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| MechanicalSoup/MechanicalSoup | `5eb3bd4a7736f3985883c08fb1707627457b1ba8` |
| jelmer/dulwich | `7897df75ee45f2d3a2f905b6336b3e0349ae125d` |
| fsspec/filesystem_spec | `778f95612ca60da45ccfb14c22b9ee409d67f1ee` |
| piskvorky/smart_open | `33915a703280e948caf7fe68002391ad9f39791f` |
| minio/minio-py | `5d3f09ccb5179b4102c00fe8bddb71564bb69e86` |
| hvac/hvac | `09902dea41c2c6313cd7844be4d984c1514bd822` |
| python-zk/kazoo | `f6a78f7e19ef57f5f5f5429c26a29176762166e6` |
| slackapi/bolt-python | `e4be52bf0b1dedb329bbd0cdfad69f4e44bbf5f9` |
| twisted/treq | `99f17121ab7e42fa4f4d12578e45cf3a26e118d9` |
| ross/requests-futures | `0ad9ea666190494d8c4c558d52a474ceaf09ef7a` |

2,907 findings; 2 false; 7 either way. bolt-python's generated API pages are 2,131 of them (stylesheet and script
loads from a CDN and links, all true); without bolt-python: 776 findings, 2 false, 7 either way, 99.74% (98.84%).
False: `git remote` (which lists the remotes) and `git remote add` (which writes local configuration) reported as a
git subcommand that contacts a remote (2). Either way: a URL with no host (`ftp:///archive.7z`, `http:///blah.txt`)
reported as an address on this machine, the host being passed separately or not at all (5); paramiko's
`transport.start_server`, which negotiates as an SSH server on a connection made elsewhere, reported as a listener (2).
All three classes were fixed in the build that ships. 127 of the 2,907 findings are of the three kinds that claim less: `unresolved-call` (109),
`external-url` in markup (17) and `script-network-word` (1).

## Set 21 (measured on an earlier build of 1.1.0, 98.8%; 96.6% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| jschneier/django-storages | `85928d63673190af4d689c9cad0e2ffaca21480a` |
| evansd/whitenoise | `51c46352bba8aa12d4538c00b5e2042e825662bc` |
| dynaconf/dynaconf | `455ee38569d76cd3707c73209b660cf60bd97b29` |
| copier-org/copier | `38f9bb042f079009e5a52b5f7acf9dba17646690` |
| pypa/flit | `75b1c909d587c1ff5e0fd5f3df1046f74ee249d4` |
| tox-dev/pipdeptree | `e45ca187af0fcea5f61760da5258c3c105e16761` |
| twisted/towncrier | `b8d90be2b1dc3c982b0de95cf02db994ce595c06` |
| commitizen-tools/commitizen | `f565e813590cd3a5af30345031a55c7cbad39402` |
| joke2k/django-environ | `9c1fc30b2b2330f297187904190c3baf80919876` |
| adamchainz/django-cors-headers | `8d96f0172cfa611124c4dc6eee14ee4a45e67589` |

582 findings; 7 false; 13 either way. False: `get = get_repo` and then `get("https://...")` in a test, a local
function that rewrites an address, reported as a call (6); an `<a href>` inside an SVG diagram, reported as a load (1).
Either way: local Mercurial subcommands (`hg status`, `hg add`, `hg branch`, `hg init`, `hg commit`, `hg files`,
`hg rm`) reported as a network-capable program run without a shell (12); `from wsgiref.simple_server import demo_app` reported as a
listener (1). All four classes were fixed in the build that ships: the call is `unresolved-call`, the SVG anchor's
address is `external-url`, Mercurial is judged by its subcommand, and `demo_app` is a dependency.

## Set 20 (measured on an earlier build of 1.1.0, 99.5%; 98.6% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| laurentS/slowapi | `d3442b2e1425a9db535732a0a06248470c7f9fd5` |
| aio-libs/aiocache | `ae5948b2d99dcaa68fe02fd3086a3351a867c85b` |
| web-push-libs/pywebpush | `4a2b66dae1408a19eb2c3f724ef0792f5258e72b` |
| miguelgrinberg/python-engineio | `740d905780f559aa4ae66f80d2cec401174f80f2` |
| ktbyers/netmiko | `410e627d15eefe4b2b8b43d1d41229e4ffcb9cd4` |
| jborean93/smbprotocol | `3acc9843483716a1d0c033e3368675ea8419fb1f` |
| giampaolo/pyftpdlib | `839ce0aa57d091873b56eaa657fca11e3dd23937` |
| aio-libs/aioftp | `4c18bdec8eb8f2e12a226fc513d07b92b5014167` |
| ronf/asyncssh | `b5f0c93a6fdb4bf86e491bde35284d82346c1a67` |
| fastapi-users/fastapi-users | `e9c57ff7ff2fd385bb0f6f795b524e9736b64290` |

2,207 findings; 11 false; 20 either way. 1,455 of the findings are in netmiko, most of them one line repeated in its
generated API pages; without netmiko: 752 findings, 10 false, 20 either way (98.7%; 96.0%). False: asyncio's own
`open_unix_connection` and an event loop's `create_unix_connection` called a network connection (9);
`connect_write_pipe` called a network connection (1); `SSH` inside text printed by `echo` before a joined command (1).
Either way: `start_server`, `create_server` and their Unix forms called on an SSH connection or an SSH tunnel, which
ask the far host to listen (20). Fixed in the build that ships: in a file that imports asyncssh, and in asyncssh's own
source, such a call is not taken as asyncio's.

## Set 19 (measured on an earlier build of 1.1.0, 94.0%; 93.4% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| tomerfiliba/plumbum | `1829ffb0f29de0328ced31d96270afa7f85bdce7` |
| amoffat/sh | `5e1c810236225ab9a41280cc1a7d9d38ef575086` |
| marshmallow-code/apispec | `9b7004866f3a7477f9b22fac0139984179cbe71e` |
| pallets-eco/cachelib | `b57f4fddb3efdfa2f385050b9e2052581933da5a` |
| mvantellingen/python-zeep | `1b7072c0dba397b86e8a47cf766a39f981b3a2de` |
| python-validators/validators | `70de324322def13a49a93d222f798ec1ab700885` |
| cannatag/ldap3 | `c5be4b6f0d32a1cbb0f81918dd8994418b6c74aa` |
| pallets-eco/flask-mail | `98203358d836788ab96e6125489895d71e9d99a3` |
| python-babel/flask-babel | `869715cfea201086d70d945fadc32ab13bbd6b68` |
| danielfm/pybreaker | `2b0b965fcfc7705ca9a776c614ea6cb3ec3fe783` |

183 findings; 11 false; 1 either way. False: `get(url)` on a cache object in tests (7); `post(url, content=...)` on
a test double bound by `with requests_mock.mock() as m` (3); `ssh` inside `--run-optional-tests=ssh,sudo` (1).
Either way: `redis-cli -p 6360 ping`, a network-capable program asked about this machine (1).

## Set 18 (measured on an earlier build of 1.1.0, 99.6%; 99.1% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| marshmallow-code/webargs | `abe0d763aeb4158764b8be3e19e36ce49c95ec8c` |
| pallets-eco/flask-caching | `f1ccf5b7476910c6b23719110fb3c9cd8e25664a` |
| alisaifee/flask-limiter | `0e715b6fbb4655756f747c78d95d61deaa69dd1c` |
| corydolphin/flask-cors | `ad4f355791dc251227a48a35419f5f144e44a22f` |
| mpdavis/python-jose | `018b310ddb8b50dcfd09a0c152117835a21dd656` |
| pyauth/pyotp | `cc156832fa9f3d5af7fb9e4e6b86b29dfc5b69f1` |
| jd/tenacity | `8be01b1daf2010566fd936a5c2214efefa43edff` |
| gruns/furl | `46d9ea79c98bb14b970a199fb924705d024f29ad` |
| python-hyper/rfc3986 | `faa2b5b018985e875cd1eff2db04cae4165ebc03` |
| litl/backoff | `d82b23c42d7a7e2402903e71e7a7f03014a00076` |

226 findings; 1 false; 1 either way. False: `uv pip uninstall` reported as reaching the network. Either way:
`redis-cli -p 6360 ping`.

## Set 17 (measured on an earlier build of 1.1.0, 99.8%; 99.4% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| python-restx/flask-restx | `30abd919e7c6bb2533eef57ec9c2339d7de69b39` |
| maxcountryman/flask-login | `c8bba84b9ba6768e878317fc46c54bd13fa1ac07` |
| pallets-eco/flask-wtf | `63e2d71269d7568307799cf43d1ee11f2d859b98` |
| PyCQA/bandit | `68ebe11ef79263be27ec223184b94a4fc394a622` |
| pypa/pip-audit | `828e77a4d4aa6bee8d315681db6928771d951a7c` |
| ansible/ansible-lint | `f9364be9c91e7060cd85fca3656879219ea1ae88` |
| jazzband/tablib | `a36c9654742d0cf07675a79df10581b3e1344555` |
| django-crispy-forms/django-crispy-forms | `e7fbb538595dde3a4598b4403e60ecca0905fa74` |
| marshmallow-code/flask-smorest | `3440f0d851f9e7f7b94d5559df3ab59746f5f6ca` |
| miguelgrinberg/Flask-HTTPAuth | `9ff38c687513d7395764bc66ffd47350d4447687` |

527 findings; 1 false; 2 either way. 199 of the findings are in bandit, whose `examples/` folder is insecure code on
purpose. False: `schema.get("$id", "http://localhost/schema.json")`, a key looked up with a default, reported as a
call. Either way: `not_requests.get('https://...')` on a name the file never defines; `Popen('/bin/rsync *')`, a
string worded as an argument list.

## Set 16 (measured on an earlier build of 1.1.0, 99.9%; tuning data now)

| Repository | Commit |
|---|---|
| jupyter/jupyter_client | `978361b3785dcd9cba6c733f4555e833e88fc0df` |
| sphinx-doc/sphinx-autobuild | `c9b7cb990e9bec1c433f737329b92655adc39a9d` |
| readthedocs/sphinx_rtd_theme | `795de79c8b311592f5863a25307d85924bf52164` |
| aws/chalice | `bbe2745e75b9aeea0c5f00296c349de22235d54c` |
| python-gitlab/python-gitlab | `51eb17e6e67a25157e04b0abc649221bd8ecc7fe` |
| requests-cache/requests-cache | `e7f0f73a8194a89497f41f8556334d8993ebee2a` |
| betamaxpy/betamax | `8f3d284103676a43d1481b5cffae96f3a601e0be` |
| kevin1024/vcrpy | `c599974b31f3e510df9b98e61513fe6889a50db0` |
| Pylons/webob | `c0d70f985ff6f04dcc59822ca5216cfd0ada666c` |
| scrapy/w3lib | `c0352eb9d2a729dd597ebae55206669fff4edb8d` |

734 findings; 1 false; 0 either way. False: `uv pip check`, which fetches nothing, reported as reaching the network.

## Set 15 (measured on an earlier build of 1.1.0, 99.7%; 99.3% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| agronholm/anyio | `eef3a156e7fd7a0974dc3e60ff00f55d0b52146e` |
| python-arq/arq | `5ee4b48cf6faf4dc181f1ccb76dfb1bc1fedf9bf` |
| jazzband/django-axes | `d1b705cff19d8601ccbf77efc1ddd06bbf5f230c` |
| jazzband/djangorestframework-simplejwt | `a7cb077ea0809f78cc6a99cb6825ab7594eae627` |
| jazzband/django-oauth-toolkit | `172ab1db500cf08232d76c43e46376eed87eceba` |
| aio-libs/aiohttp-session | `5060d64ba2447376132ac62ccebe9e9bab3057a0` |
| python-hyper/h2 | `bc239af1d1b85bc70482804f30a0e0e587d90a08` |
| encode/broadcaster | `6b3ea71d4f8fb038fa7d357a1fb3750d58ac614d` |
| pypa/virtualenv | `95d02526dc5f2c569767d8ee572f72f571b8a6ce` |
| pypa/hatch | `7c26ebeaf8b83f5f0374a2545bb15e36c87db0d0` |

1,264 findings; 4 false; 5 either way. The four false claims and three of the either-way claims were fixed afterwards, each class with a test.

## Set 14 (measured on an earlier build of 1.1.0, 99.9%; 98.2% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| dbcli/pgcli | `101e523eb2987ada87231c4533f0ab701c4c3124` |
| dbcli/mycli | `bddbffc781b8a1ae7352cd575fa8ade6b6aa3da4` |
| lepture/authlib | `c529a61af40e3efe05286140e00fbdced07d7987` |
| oauthlib/oauthlib | `16801a6f98e4bcbf4d38ae8ebd75e01b1b525cbc` |
| jpadilla/pyjwt | `b5bd6fe6d7ac0370ba90557c7a1e3d50a9414572` |
| python-social-auth/social-core | `156082ef69ed3a0892fdf985b8739eecef50faae` |
| celery/django-celery-beat | `e5e21ddbf43fdb3442b2cd7c6272dd0bf1c33d26` |
| django-extensions/django-extensions | `9bdf31556675e795c7c7c4f033f194dc075d5919` |
| jazzband/django-silk | `5e88c839b65a73d1fbc4d41f9886c81c45c94eec` |
| coleifer/walrus | `81a4c03d71ca3ecc111d8cbac542a92d606128b5` |

1,346 findings; 2 false; 22 either way. Fixed afterwards, each class with a test.

## Set 13 (measured on an earlier build of 1.1.0, 100%; 99.6% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| errbotio/errbot | `af1bb75b933178cf4dc5ddc8a0e327d2c2bc21d8` |
| mikf/gallery-dl | `6f7e9c62a56fcc48f76e3c3cc8fa238e42cf25b5` |
| scrapy/scrapyd | `7e8b2533c647c3bab06c2ac683f97b881dd9228b` |
| nameko/nameko | `3355677f2f514d5feb67b399a0b48ebeac0d4648` |
| twilio/twilio-python | `2fd57cf8f344c472c6e3b14205ad266d1bd6babc` |
| stripe/stripe-python | `29363094b09a67f8b1b50f577b463edbbb27ec9a` |
| sendgrid/sendgrid-python | `76788e70a76b11ce2990821f190e52f887ab9ed6` |
| pinterest/pymemcache | `3ef28efac1a6cca5fb47c88981b7df4b33f1aac5` |
| zulip/python-zulip-api | `b172347594a4634517f925f9e30522fe987dbb9c` |
| miguelgrinberg/Flask-Migrate | `bce4d35a0c61d2516c76744a1f168bc6af26d55e` |

731 findings; 0 false; 3 either way. All three were fixed afterwards, each class with a test.

## Set 12 (measured on an earlier build of 1.1.0, 99.97%; 99.9% without one repository's generated API pages; tuning data now)

| Repository | Commit |
|---|---|
| python-telegram-bot/python-telegram-bot | `d4f2b1682938710be93332c08be543a683e414e6` |
| PyGithub/PyGithub | `9152817c2d437282d46e7822e825dcf7e3a3e947` |
| praw-dev/praw | `718b90c75e0f8758d45db75e33b7d72e430d026a` |
| spotipy-dev/spotipy | `351d4223d0aa2f8417fb2d51c529f3564ecdc4dc` |
| slackapi/python-slack-sdk | `dd615799e83ff20cd6b6acd2909ea19604679ef1` |
| websocket-client/websocket-client | `318d1bc3b8de4b1dc2c9ea49d4b4825d200cff13` |
| jupyterhub/jupyterhub | `1dd5f4c3c0d928bdf8363bcee2456de6f2499134` |
| ipython/ipykernel | `cfa461d8afac05cefc3671128d00adaa3c0720f4` |
| pytest-dev/pytest-django | `b030393c6f192a2145b8fda286f0a6c4d3ee0992` |
| kurtmckee/feedparser | `a22c5521cbb109871f1a2318948581901bd47e26` |

3,282 findings; 1 false; 3 either way. The false claim was fixed afterwards and the either-way claims re-classified, each with a test.

## Set 11 (measured on an earlier build of 1.1.0, 99.4%; 98.5% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| getsentry/sentry-python | `8afefe81d014cc6bffffca28c18e1219f545d49f` |
| psf/requests-html | `075ac162dc62fc532037df0d98954ab840a97516` |
| tweepy/tweepy | `c1978d643ecce491929084e4290b35f57e4921ad` |
| eclipse-paho/paho.mqtt.python | `b48baeee24b08499a6683c7b67746e08be6696f5` |
| pika/pika | `e2822a005b49f7f75e7fe4a82d3c84a9424dbcdf` |
| celery/kombu | `fd8aa520d81b5265729d38877f094008c232b836` |
| miguelgrinberg/microdot | `7742db9ff9f49635de3387145fafe56bf2377a97` |
| Pylons/waitress | `2b43237e9caa66f906d0f652f2519cc79ef969a5` |
| cherrypy/cheroot | `2aa0a25c775d7d66bce27f487de94072ba62ebc2` |
| simonw/sqlite-utils | `6bc1d33d583c54bd69fbdd2071117e2d38c354a1` |

1,426 findings; 8 false; 14 either way. All eight false claims were fixed afterwards and thirteen either-way claims re-classified, each class with a test.

## Set 10 (measured on an earlier build of 1.1.0, 100%; 97.6% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| simonw/datasette | `cec5e6b2ef5d33eda31f9be092c4ec174ff0c5e9` |
| aio-libs/aiosmtpd | `07e5f26b0c27a10c71b860c0ebd699f369c4c6e0` |
| jazzband/django-redis | `d646a755e13dee8861e15ac515cfe785ebf78274` |
| mher/flower | `ea34f92dc4c898a6788af13ec8e36d1d53d357d1` |
| jupyter/nbconvert | `1ff189e1b30f0820238e95427c035a9150a5e43f` |
| pyca/pyopenssl | `567808adb4d859323424c3a6bc183e13a1ac59e8` |
| python-poetry/cleo | `8c3f1bbf82d918fc137ad40db65c446e14564aac` |
| psf/httpbin | `f7b02ae1c6f760a26d08e0e080097e6c9b2cc923` |
| mopidy/mopidy | `95ccdbea043226ed3305e0444aa30fe31ce4c18e` |
| pallets-eco/flask-sqlalchemy | `80ac6ef26bd12a6b5472a494d541a7d2442a38a4` |

633 findings; 0 false; 15 either way. All fifteen either-way claims were re-classified afterwards, each class with a test.

## Set 9 (measured on an earlier build of 1.1.0, 99.8%; 99.1% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| coleifer/huey | `817e0fdddf356f1129764bae7083628ff4363729` |
| pyinvoke/invoke | `6a71e680c535ba6520e935c497099fbca011d03c` |
| pahaz/sshtunnel | `dc0732884379a19a21bf7a49650d0708519ec54f` |
| pytest-dev/pytest-xdist | `eba6a4475eb8697fc476357ff54d7b8b948781cf` |
| jazzband/django-debug-toolbar | `69c5a8e43375f3d447419d149eca17c261f6555e` |
| miguelgrinberg/python-socketio | `5b49d7ca33e5eedecf94e35301a847ae0d2bd52b` |
| getsentry/responses | `175ec74a87600c4f638a8c51adf4fcd389906c8a` |
| Kozea/WeasyPrint | `369b15340ea97c5d649af65e8e10330b8d08f01f` |
| lektor/lektor | `9ebd5dcbaa44f50c59e971c2e1d22039c548e230` |
| nteract/papermill | `e4e4ddd362037309c53ab5230541759707779687` |

1,047 findings; 2 false; 7 either way. Both false claims were fixed afterwards, each class with a test.

## Set 8 (measured on an earlier build of 1.1.0, 99.7%; 99.2% without one repository's generated test pages; tuning data now)

| Repository | Commit |
|---|---|
| getpelican/pelican | `3c69dc68d25a761911697467c765a16e68915c74` |
| pre-commit/pre-commit | `368bf4761eb2edc71b73a92e5537505df2b8a84c` |
| nicolargo/glances | `89da4c90e827d7d3761ccf8441af11fa9393120d` |
| coleifer/peewee | `bea93b9c5b02ab0e5ba30e5c2f7f0e0246c1e695` |
| beetbox/beets | `ad758c1ceb4e84adcd0508751a6ba4224ee28954` |
| Bogdanp/dramatiq | `e9e7c4312308a8c7c27896c64a6f437af07dce18` |
| rq/rq | `bd339ae3d12d94fb9b01013a1c1fd880f7aea93e` |
| cherrypy/cherrypy | `1f75bc9eed8e0e385f64f368bd69f58d96fb8c2b` |
| wntrblm/nox | `d32f3de1643c71c0a24e6f5524aa8ce1cfb8a223` |
| python-zeroconf/python-zeroconf | `f0c27b38ea02484d7bb96f4d06e8e1941c4525f9` |

1,870 findings; 6 false; 9 either way. All six false claims were fixed afterwards, each class with a test.

## Set 7 (measured on an earlier build of 1.1.0, 99.6%; 98.5% without one repository's snapshot files; tuning data now)

| Repository | Commit |
|---|---|
| pallets/quart | `29d339c87f9efd1ba5268666e2404530fe078911` |
| sqlalchemy/alembic | `b42ebe1ff576e02b8bfc9ef1c3c3a5fd1ac41bf4` |
| Textualize/textual | `06dbeef4bb70fb718236aa418ed658ef4667a126` |
| pypa/pipx | `38f3575838f9608154bf38e891ea001294df5521` |
| miguelgrinberg/Flask-SocketIO | `f63afe0aa9c8ea52b0e624098689c76be108e5ed` |
| nvbn/thefuck | `c7e7e1d884d3bb241ea6448f72a989434c2a35ec` |
| streamlink/streamlink | `50843077b2629af00fdacd954337164d73db3262` |
| spotify/luigi | `715f65c4a56a908ef0a1df4df6fc33b8420e2e6c` |
| mkdocs/mkdocs | `2862536793b3c67d9d83c33e0dd6d50a791928f8` |
| fabric/fabric | `ded51893f02c33d2bc7c157624c44a039a952037` |

2,689 findings; 10 false; 5 either way. Its false classes were fixed afterwards, each with a test.

## Set 6 (measured on an earlier build of 1.1.0, 96.8%; tuning data now)

| Repository | Commit |
|---|---|
| encode/django-rest-framework | `41764f1f8cfb6d40b77b58c97cf9aeaab57c6b5c` |
| python-poetry/poetry | `d4fd21e4711ae948f04e18a1736d9ee85b590e87` |
| pypa/twine | `f536ac5d0c77a24a997854328e64644f576b4992` |
| boto/boto3 | `97c94267beacd31360bdcde884cd294215bb3341` |
| mitmproxy/mitmproxy | `be758251c42116a17a1d7236d020af603fd82ef7` |
| locustio/locust | `555ad9e5dcf510aa48d166054019cb176afcf84b` |
| Pylons/pyramid | `948c6bac3b8ec5160e85e3bf9653c767c978ed94` |
| mongodb/mongo-python-driver | `07a7b8e0066ae409bcdcaf23e83b4b72f9f97b35` |
| Delgan/loguru | `48acf77ac2b3296acc67069511b99cc3ca3d0c41` |
| cookiecutter/cookiecutter | `c88fbe921c97c58b65f1883ba90a0ab53cc91b34` |

2,014 findings; 64 false; 54 either way. Every false class it showed is handled in the version that ships.

## Set 5 (measured on an earlier build of 1.1.0, 98.9%; 75.4% counting either-way claims as false; tuning data now)

| Repository | Commit |
|---|---|
| aio-libs/aiohttp | `a6306fc439f29b5295626c25475cc56b011a0742` |
| tornadoweb/tornado | `7c60d94d900dc32a46a6d436fa5a2d24135892c6` |
| redis/redis-py | `a3913aeddf42479af0094a8361fc00dd993fd592` |
| celery/celery | `e0dfab2d06b5c0b42d2df049f1f1106cc76fba5a` |
| scrapy/scrapy | `e49bc32d0ed875f4958bbe28210d5319e9f2c9ae` |
| encode/httpcore | `10a658221deb38a4c5b16db55ab554b0bf731707` |
| pydantic/pydantic | `e87e11b7a74068c2d8107e48ffed6102744abef8` |
| psf/black | `994ef7eeb18172178552daa1f36f001d156ad583` |
| tox-dev/tox | `a45f1fa79a0fc2acbafdb64e2cff9325420be0ae` |
| docker/docker-py | `56343ddf8f0c44281e151c2dad016c16cdb8393d` |

2,779 findings; 30 false; 653 either way. Audited on Windows with line endings as checked out; the findings digest
does not depend on that. Every false class it showed is handled in the version that ships.

## Set 4: installed packages, measured on an earlier build of version 1.1.0

Not repositories at a commit: the packages as installed from PyPI into one environment, read where they sat.
Each row is a distribution and its version. `attrs` was in that environment and is left out, because it is in
an earlier set.

| Distribution | Version |
|---|---|
| hypothesis | 6.168.3 |
| pip | 26.2.1 |
| setuptools | 84.0.0 |
| pygments | 2.21.0 |
| jsonschema | 4.26.0 |
| jsonschema-specifications | 2025.9.1 |
| referencing | 0.37.0 |
| rpds-py | 2026.6.3 |
| pytest | 9.1.1 |
| pluggy | 1.6.0 |
| packaging | 26.3 |
| iniconfig | 2.3.0 |
| colorama | 0.4.6 |
| sortedcontainers | 2.4.0 |
| wheel | 0.48.0 |

1,276 findings; 2 false; 1,084 either way (1,083 of them pip importing its own modules). The classes found are
handled in the version that ships, so this set is tuning data now. Re-read in full on 1.1.0 as shipped: 197
findings, none false (`import socks` inside pip's vendored `contrib/socks.py`, taken as that module, was the last
class and is fixed).
