/*
 * Copyright (c) 2013-2017 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

// only for win32
#ifndef WIN32
#error "This file only for Windows"
#endif
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "ifaddrs.h"

#define FI_SUCCESS 0
#define	FI_ENOMEM		ENOMEM		/* Out of memory */
#define	FI_ENODATA		ENODATA		/* No data available */

int getifaddrs(struct ifaddrs **ifap)
{
	ULONG subnet = 0;
	PULONG mask = &subnet;
	DWORD size, res, i = 0;
	int ret;
	PIP_ADAPTER_ADDRESSES adapter_addresses, aa;
	PIP_ADAPTER_UNICAST_ADDRESS ua;
	struct ifaddrs *head = NULL;
	struct sockaddr_in *pInAddr = NULL;
	SOCKADDR *pSockAddr = NULL;
	struct ifaddrs *fa;

	res = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX,
				   NULL, NULL, &size);
	if (res != ERROR_BUFFER_OVERFLOW)
		return -FI_ENOMEM;

	adapter_addresses = (PIP_ADAPTER_ADDRESSES)malloc(size);
	res = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX,
				   NULL, adapter_addresses, &size);
	if (res != ERROR_SUCCESS)
		return -FI_ENOMEM;

	for (aa = adapter_addresses; aa != NULL; aa = aa->Next) {
		if (aa->OperStatus != 1)
			continue;

		for (ua = aa->FirstUnicastAddress; ua != NULL; ua = ua->Next) {
			pSockAddr = ua->Address.lpSockaddr;
			if (pSockAddr->sa_family != AF_INET &&
				pSockAddr->sa_family != AF_INET6)
				continue;
			fa = calloc(sizeof(*fa), 1);
			if (!fa) {
				ret = -FI_ENOMEM;
				goto out;
			}

			fa->ifa_next = head;
			head = fa;

			fa->ifa_flags = IFF_UP;
			if (aa->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
				fa->ifa_flags |= IFF_LOOPBACK;

			fa->ifa_addr = (struct sockaddr *) &fa->in_addrs;
			fa->ifa_netmask = (struct sockaddr *) &fa->in_netmasks;
			fa->ifa_name = fa->ad_name;

			if (pSockAddr->sa_family == AF_INET) {
				subnet = 0;
				mask = &subnet;
				if (ConvertLengthToIpv4Mask(ua->OnLinkPrefixLength, mask) !=
					NO_ERROR) {
					ret = -FI_ENODATA;
					goto out;
				}
				struct sockaddr_in *addr4 = (struct sockaddr_in *)
							    &fa->in_addrs;
				struct sockaddr_in *netmask4 = (struct sockaddr_in *)
								&fa->in_netmasks;
				netmask4->sin_family = pSockAddr->sa_family;
				addr4->sin_family = pSockAddr->sa_family;
				netmask4->sin_addr.S_un.S_addr = *mask; // mask?
				pInAddr = (struct sockaddr_in *) pSockAddr;
				addr4->sin_addr = pInAddr->sin_addr;
			} else {
				struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)
							      &fa->in_addrs;
				(*addr6) = *(struct sockaddr_in6 *) pSockAddr;
			}
			fa->speed = aa->TransmitLinkSpeed;
			/* Generate fake Unix-like device names */
			sprintf_s(fa->ad_name, sizeof(fa->ad_name), "eth%d", i++);
		}
	}
	ret = FI_SUCCESS;
out:
	free(adapter_addresses);
	if (ret && head)
		free(head);
	else if (ifap)
		*ifap = head;

	return ret;
}

void freeifaddrs(struct ifaddrs *ifa)
{
	while (ifa) {
		struct ifaddrs *next = ifa->ifa_next;
		free(ifa);
		ifa = next;
	}
}

