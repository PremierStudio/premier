# Third-party notices

Premier is licensed under Apache-2.0 OR MIT. It includes and links against open-source software from other authors. This file lists notices for components whose licenses ask for attribution beyond the usual Apache-2.0/MIT dual license. Every dependency's own license text ships with its source on crates.io or npm, and `cargo deny check licenses` (see `deny.toml`) verifies that each one is on the allowed list.

## Rust dependencies

### curve25519-dalek, ed25519-dalek, x25519-dalek

BSD-3-Clause.

Copyright (c) 2016-2021 isis agora lovecruft. All rights reserved.
Copyright (c) 2016-2024 Henry de Valence. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### subtle

BSD-3-Clause, under the same terms as above.

Copyright (c) 2016-2017 isis agora lovecruft, Henry de Valence. All rights reserved.

### ring

Apache-2.0 AND ISC. Parts of *ring* are derived from BoringSSL and OpenSSL; see the `LICENSE` files distributed with the crate for the full notices.

Copyright Brian Smith and the *ring* contributors.

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

### rustls-webpki, untrusted

ISC, under the permission notice above.

Copyright 2015 Brian Smith. Copyright the rustls-webpki contributors.

### webpki-roots

CDLA-Permissive-2.0 (Community Data License Agreement – Permissive, Version 2.0). The crate contains root certificate data derived from the Mozilla CA Certificate Program, distributed through the Common CA Database. Full text: <https://cdla.dev/permissive-2-0/>.

### matchit

MIT AND BSD-3-Clause. Portions are derived from [httprouter](https://github.com/julienschmidt/httprouter).

Copyright (c) 2013 Julien Schmidt. All rights reserved. Redistribution and use are permitted under the BSD-3-Clause terms reproduced above.

### zlib-rs

Zlib.

Copyright the zlib-rs contributors. Derived from zlib, Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler.

This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.

Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.

### ICU4X (icu_*, zerovec, yoke, tinystr, writeable, litemap and related crates), unicode-ident

Unicode-3.0.

Copyright © 1991-2025 Unicode, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of data files and any associated documentation (the "Data Files") or software and any associated documentation (the "Software") to deal in the Data Files or Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, and/or sell copies of the Data Files or Software, and to permit persons to whom the Data Files or Software are furnished to do so, provided that either (a) this copyright and permission notice appear with all copies of the Data Files or Software, or (b) this copyright and permission notice appear in associated Documentation.

THE DATA FILES AND SOFTWARE ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR HOLDERS INCLUDED IN THIS NOTICE BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THE DATA FILES OR SOFTWARE.

Except as contained in this notice, the name of a copyright holder shall not be used in advertising or otherwise to promote the sale, use or other dealings in these Data Files or Software without prior written authorization of the copyright holder.

## Other dependencies

All other Rust crates used by Premier are available under MIT, Apache-2.0, or a choice that includes one of them. The Studio's JavaScript dependencies are listed in `apps/web/package.json` with their versions in `apps/web/pnpm-lock.yaml`; each package's license is in its own distribution.

---

### Bundled icon assets

The Studio bundles a small set of SVG icons in `apps/web/src/assets/brand-icons/` so it works offline. They come from [homarr-labs/dashboard-icons](https://github.com/homarr-labs/dashboard-icons), licensed under the Apache License, Version 2.0. The product names and logos they depict are trademarks of their respective owners, used only to identify integrations; no endorsement or affiliation is implied. See `apps/web/src/assets/brand-icons/ATTRIBUTION.md`.
