#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <wdns.h>

/* Hex string decoder - handles both continuous and space-separated hex */
static bool
hex_to_int(char hex, uint8_t *val)
{
	if (islower((unsigned char) hex))
		hex = toupper((unsigned char) hex);

	switch (hex) {
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
		*val = (hex - '0');
		return (true);
	case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
		*val = (hex - 55);
		return (true);
	default:
		return (false);
	}
}

static bool
hex_decode(const char *hex, uint8_t **raw, size_t *len)
{
	uint8_t *p;
	const char *src = hex;
	size_t count = 0;

	/* Count hex digit pairs (skip spaces) */
	while (*src) {
		if (*src == ' ' || *src == '\t' || *src == '\n') {
			src++;
			continue;
		}
		if (!isxdigit((unsigned char)*src)) {
			fprintf(stderr, "Invalid hex character: %c\n", *src);
			return (false);
		}
		count++;
		src++;
	}

	if (count % 2 != 0) {
		fprintf(stderr, "Odd number of hex digits\n");
		return (false);
	}

	*len = count / 2;
	p = *raw = malloc(*len);
	if (*raw == NULL) {
		fprintf(stderr, "malloc failed\n");
		return (false);
	}

	src = hex;
	while (*src) {
		uint8_t val[2];

		/* Skip whitespace */
		while (*src && (*src == ' ' || *src == '\t' || *src == '\n'))
			src++;

		if (!*src)
			break;

		/* Get first nibble */
		if (!hex_to_int(*src, &val[0])) {
			fprintf(stderr, "Invalid hex digit: %c\n", *src);
			goto err;
		}
		src++;

		/* Get second nibble */
		if (!hex_to_int(*src, &val[1])) {
			fprintf(stderr, "Invalid hex digit: %c\n", *src);
			goto err;
		}
		src++;

		*p = (val[0] << 4) | val[1];
		p++;
	}

	return (true);
err:
	free(*raw);
	return (false);
}

/* Pretty print a domain name */
static void
print_name(const uint8_t *name, size_t len)
{
	char buf[4096];
	wdns_domain_to_str(name, len, buf);
	printf("%s", buf);
}

/* Print a single resource record */
static void
print_rr(const wdns_rr_t *rr, unsigned sec)
{
	char *rr_str = wdns_rr_to_str((wdns_rr_t *)rr, sec);
	if (rr_str) {
		printf("%s\n", rr_str);
		free(rr_str);
	}
}

/* Pretty print DNS message */
static void
print_dns_message(const wdns_message_t *m)
{
	printf(";; ->>HEADER<<- ");
	printf("opcode: %s, status: %s, id: %u\n",
		wdns_opcode_to_str(WDNS_FLAGS_OPCODE(*m)),
		wdns_rcode_to_str(m->rcode),
		m->id);

	printf(";; flags: ");
	if (WDNS_FLAGS_QR(*m)) printf("qr ");
	if (WDNS_FLAGS_AA(*m)) printf("aa ");
	if (WDNS_FLAGS_TC(*m)) printf("tc ");
	if (WDNS_FLAGS_RD(*m)) printf("rd ");
	if (WDNS_FLAGS_RA(*m)) printf("ra ");
	if (WDNS_FLAGS_AD(*m)) printf("ad ");
	if (WDNS_FLAGS_CD(*m)) printf("cd ");
	printf("\n");

	/* Count records in each section */
	unsigned qdcount = m->sections[WDNS_MSG_SEC_QUESTION].n_rrs;
	unsigned ancount = m->sections[WDNS_MSG_SEC_ANSWER].n_rrs;
	unsigned nscount = m->sections[WDNS_MSG_SEC_AUTHORITY].n_rrs;
	unsigned arcount = m->sections[WDNS_MSG_SEC_ADDITIONAL].n_rrs;

	printf(";; QUESTION SECTION:\n");
	for (unsigned i = 0; i < qdcount; i++) {
		wdns_rr_t *rr = &m->sections[WDNS_MSG_SEC_QUESTION].rrs[i];
		printf(";");
		print_name(rr->name.data, rr->name.len);
		printf(" %s %s\n",
			wdns_rrclass_to_str(rr->rrclass),
			wdns_rrtype_to_str(rr->rrtype));
	}

	if (ancount > 0) {
		printf("\n;; ANSWER SECTION:\n");
		for (unsigned i = 0; i < ancount; i++) {
			wdns_rr_t *rr = &m->sections[WDNS_MSG_SEC_ANSWER].rrs[i];
			print_rr(rr, WDNS_MSG_SEC_ANSWER);
		}
	}

	if (nscount > 0) {
		printf("\n;; AUTHORITY SECTION:\n");
		for (unsigned i = 0; i < nscount; i++) {
			wdns_rr_t *rr = &m->sections[WDNS_MSG_SEC_AUTHORITY].rrs[i];
			print_rr(rr, WDNS_MSG_SEC_AUTHORITY);
		}
	}

	if (arcount > 0) {
		printf("\n;; ADDITIONAL SECTION:\n");
		for (unsigned i = 0; i < arcount; i++) {
			wdns_rr_t *rr = &m->sections[WDNS_MSG_SEC_ADDITIONAL].rrs[i];
			print_rr(rr, WDNS_MSG_SEC_ADDITIONAL);
		}
	}

	if (m->edns.present) {
		printf("\n;; OPT PSEUDO-SECTION:\n");
		printf("; EDNS: version %u, flags 0x%04x, UDP size %u\n",
			m->edns.version,
			m->edns.flags,
			m->edns.size);
		if (m->edns.options && m->edns.options->len > 0) {
			printf("; EDNS options: %u bytes\n", m->edns.options->len);
		}
	}

	printf("\n");
}

/* JSON output helper - escape strings */
static void
json_escape_string(const char *str)
{
	putchar('"');
	while (*str) {
		switch (*str) {
		case '"': printf("\\\""); break;
		case '\\': printf("\\\\"); break;
		case '\n': printf("\\n"); break;
		case '\r': printf("\\r"); break;
		case '\t': printf("\\t"); break;
		default:
			if (*str >= 32 && *str < 127)
				putchar(*str);
			else
				printf("\\u%04x", (unsigned char)*str);
		}
		str++;
	}
	putchar('"');
}

/* Output DNS message as JSON */
static void
output_json(const wdns_message_t *m)
{
	printf("{\n");
	printf("  \"header\": {\n");
	printf("    \"id\": %u,\n", m->id);
	printf("    \"flags\": %u,\n", m->flags);
	printf("    \"opcode\": \"%s\",\n", wdns_opcode_to_str(WDNS_FLAGS_OPCODE(*m)));
	printf("    \"rcode\": \"%s\",\n", wdns_rcode_to_str(m->rcode));
	printf("    \"qr\": %s,\n", WDNS_FLAGS_QR(*m) ? "true" : "false");
	printf("    \"aa\": %s,\n", WDNS_FLAGS_AA(*m) ? "true" : "false");
	printf("    \"tc\": %s,\n", WDNS_FLAGS_TC(*m) ? "true" : "false");
	printf("    \"rd\": %s,\n", WDNS_FLAGS_RD(*m) ? "true" : "false");
	printf("    \"ra\": %s,\n", WDNS_FLAGS_RA(*m) ? "true" : "false");
	printf("    \"ad\": %s,\n", WDNS_FLAGS_AD(*m) ? "true" : "false");
	printf("    \"cd\": %s\n", WDNS_FLAGS_CD(*m) ? "true" : "false");
	printf("  },\n");

	/* Sections */
	printf("  \"sections\": {\n");
	printf("    \"question\": [\n");
	for (unsigned i = 0; i < m->sections[WDNS_MSG_SEC_QUESTION].n_rrs; i++) {
		wdns_rr_t *rr = &m->sections[WDNS_MSG_SEC_QUESTION].rrs[i];
		if (i > 0) printf(",\n");
		printf("      {\n");
		printf("        \"name\": ");
		char buf[4096];
		wdns_domain_to_str(rr->name.data, rr->name.len, buf);
		json_escape_string(buf);
		printf(",\n");
		printf("        \"type\": \"%s\",\n", wdns_rrtype_to_str(rr->rrtype));
		printf("        \"class\": \"%s\"\n", wdns_rrclass_to_str(rr->rrclass));
		printf("      }");
	}
	printf("\n    ],\n");

	printf("    \"answer\": [\n");
	for (unsigned i = 0; i < m->sections[WDNS_MSG_SEC_ANSWER].n_rrs; i++) {
		wdns_rr_t *rr = &m->sections[WDNS_MSG_SEC_ANSWER].rrs[i];
		if (i > 0) printf(",\n");
		printf("      {\n");
		printf("        \"name\": ");
		char buf[4096];
		wdns_domain_to_str(rr->name.data, rr->name.len, buf);
		json_escape_string(buf);
		printf(",\n");
		printf("        \"type\": \"%s\",\n", wdns_rrtype_to_str(rr->rrtype));
		printf("        \"class\": \"%s\",\n", wdns_rrclass_to_str(rr->rrclass));
		printf("        \"ttl\": %u,\n", rr->rrttl);
		printf("        \"rdlen\": %u,\n", rr->rdata ? rr->rdata->len : 0);
		char *rdata_str = wdns_rdata_to_str(rr->rdata->data, rr->rdata->len,
			rr->rrtype, rr->rrclass);
		printf("        \"rdata\": ");
		if (rdata_str) {
			json_escape_string(rdata_str);
			free(rdata_str);
		} else {
			printf("null");
		}
		printf("\n      }");
	}
	printf("\n    ],\n");

	printf("    \"authority\": [\n");
	for (unsigned i = 0; i < m->sections[WDNS_MSG_SEC_AUTHORITY].n_rrs; i++) {
		wdns_rr_t *rr = &m->sections[WDNS_MSG_SEC_AUTHORITY].rrs[i];
		if (i > 0) printf(",\n");
		printf("      { \"name\": \"%.*s\" }\n", (int)rr->name.len, rr->name.data);
	}
	printf("\n    ],\n");

	printf("    \"additional\": [\n");
	for (unsigned i = 0; i < m->sections[WDNS_MSG_SEC_ADDITIONAL].n_rrs; i++) {
		wdns_rr_t *rr = &m->sections[WDNS_MSG_SEC_ADDITIONAL].rrs[i];
		if (i > 0) printf(",\n");
		printf("      {\n");
		printf("        \"name\": ");
		char buf[4096];
		wdns_domain_to_str(rr->name.data, rr->name.len, buf);
		json_escape_string(buf);
		printf(",\n");
		printf("        \"type\": \"%s\",\n", wdns_rrtype_to_str(rr->rrtype));
		printf("        \"class\": \"%s\",\n", wdns_rrclass_to_str(rr->rrclass));
		printf("        \"ttl\": %u\n", rr->rrttl);
		printf("      }");
	}
	printf("\n    ]\n");
	printf("  },\n");

	printf("  \"edns\": {\n");
	printf("    \"present\": %s,\n", m->edns.present ? "true" : "false");
	if (m->edns.present) {
		printf("    \"version\": %u,\n", m->edns.version);
		printf("    \"flags\": %u,\n", m->edns.flags);
		printf("    \"udp_size\": %u\n", m->edns.size);
	} else {
		printf("    \"version\": null,\n");
		printf("    \"flags\": null,\n");
		printf("    \"udp_size\": null\n");
	}
	printf("  }\n");
	printf("}\n");
}

int
main(int argc, char **argv)
{
	size_t rawlen;
	uint8_t *rawdata;
	wdns_message_t msg;
	wdns_res res;
	bool json_output = false;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [-j|--json] <HEXDATA>\n", argv[0]);
		fprintf(stderr, "  -j, --json       Output as JSON\n");
		fprintf(stderr, "  HEXDATA          Space-separated or continuous hex string\n");
		return (EXIT_FAILURE);
	}

	/* Check for output format flag */
	int arg_idx = 1;
	if (strcmp(argv[arg_idx], "-j") == 0 || strcmp(argv[arg_idx], "--json") == 0) {
		json_output = true;
		arg_idx++;
	}

	if (arg_idx >= argc) {
		fprintf(stderr, "Error: missing hex data\n");
		return (EXIT_FAILURE);
	}

	/* Decode hex */
	if (!hex_decode(argv[arg_idx], &rawdata, &rawlen)) {
		fprintf(stderr, "Error: unable to decode hex\n");
		return (EXIT_FAILURE);
	}

	/* Parse DNS message */
	res = wdns_parse_message(&msg, rawdata, rawlen);
	if (res != wdns_res_success) {
		fprintf(stderr, "Error: wdns_parse_message failed: %s\n", wdns_res_to_str(res));
		free(rawdata);
		return (EXIT_FAILURE);
	}

	/* Output */
	if (json_output) {
		output_json(&msg);
	} else {
		print_dns_message(&msg);
	}

	/* Cleanup */
	wdns_clear_message(&msg);
	free(rawdata);

	return (EXIT_SUCCESS);
}
