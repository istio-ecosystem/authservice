// Copyright 2024 Tetrate
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package http

const (
	HeaderAuthorization = "authorization"
	HeaderCacheControl  = "cache-control"
	HeaderContentType   = "content-type"
	HeaderCookie        = "cookie"
	HeaderLocation      = "location"
	HeaderPragma        = "pragma"
	HeaderSetCookie     = "set-cookie"

	HeaderCacheControlNoCache = "no-cache"

	HeaderContentTypeFormURLEncoded = "application/x-www-form-urlencoded"

	HeaderPragmaNoCache = "no-cache"

	HeaderSetCookieSecure         = "Secure"
	HeaderSetCookieHTTPOnly       = "HttpOnly"
	HeaderSetCookieSameSiteStrict = "SameSite=Strict"
	HeaderSetCookieSameSiteLax    = "SameSite=Lax"
	HeaderSetCookieMaxAge         = "Max-Age"
)
