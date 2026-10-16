#include <stdio.h>
#include <stdint.h>
#include "libtss.h"
TssStatus phase_new(uint8_t hash[32], const uint8_t *session_id, size_t session_id_len, TssHandle key_shares[], TssHandle sessions[], TssBuffer outbound[], size_t party_count)
{
	TssSlice message={.data=hash, .len=32};
	for(size_t i=0; i<party_count; i++)
	{
		uint16_t counterparties[party_count-1];
		size_t n=0;
		for(size_t j=0; j<party_count; j++)
		{
			if(j!=i)
			{
				counterparties[n++]=(uint16_t)(j+1);
			}
		}
		TssStatus status=tss_sign_new(key_shares[i], message, counterparties, n, session_id, session_id_len, &sessions[i], &outbound[i]);
		if(status!=TSS_OK)
		{
			uint8_t error[1024];
			tss_last_error_copy(error, sizeof(error));
			fprintf(stderr, "tss_sign_new() failed: %s\n", error);
			return status;
		}
		printf("signing session %zu created: handle=%llu, outbound=%zu bytes\n", i+1, (unsigned long long)sessions[i], outbound[i].len);
	}
	return TSS_OK;
}
TssStatus phase_next(TssHandle sessions[], TssBuffer inbound[], TssBuffer outbound[], bool complete[], TssBuffer signatures[], size_t party_id)
{
	size_t index=party_id-1;
	TssSlice inbound_slice={.data=inbound[index].data, .len=inbound[index].len};
	TssStatus status=tss_sign_next(sessions[index], inbound_slice, &signatures[index], &outbound[index], &complete[index]);
	if(status!=TSS_OK)
	{
		uint8_t error[1024];
		tss_last_error_copy(error, sizeof(error));
		fprintf(stderr, "tss_sign_next() failed: %s\n", error);
		return status;
	}
	printf("sign next for party %zu: complete=%s, outbound=%zu bytes\n", party_id, complete[index]?"yes":"no", outbound[index].len);
	return TSS_OK;
}
TssStatus simulate_traffic(TssBuffer outbound[], TssBuffer inbound[], size_t party_count)
{
	for(size_t sender=0; sender<party_count; sender++)
	{
		TssSlice outbound_slice={.data=outbound[sender].data, .len=outbound[sender].len};
		size_t message_count=tss_message_count(outbound_slice);
		for(size_t i=0; i<message_count; i++)
		{
			uint16_t from;
			uint16_t to;
			TssSlice message;
			TssStatus status=tss_message_at(outbound_slice, i, &from, &to, &message);
			if(status!=TSS_OK)
			{
				uint8_t error[1024];
				tss_last_error_copy(error, sizeof(error));
				fprintf(stderr, "tss_message_at() failed: %s\n", error);
				return status;
			}
			if(to==0)
			{
				for(size_t recipient=0; recipient<party_count; recipient++)
				{
					uint16_t recipient_id=recipient+1;
					if(recipient_id==from)
					{
						continue;
					}
					status=tss_message_build(&inbound[recipient], from, to, message.data, message.len);
					if(status!=TSS_OK)
					{
						uint8_t error[1024];
						tss_last_error_copy(error, sizeof(error));
						fprintf(stderr, "tss_message_build() failed: %s\n", error);
						return status;
					}
				}
			}
			else
			{
				size_t recipient=to-1;
				status=tss_message_build(&inbound[recipient], from, to, message.data, message.len);
				if(status!=TSS_OK)
				{
					uint8_t error[1024];
					tss_last_error_copy(error, sizeof(error));
					fprintf(stderr, "tss_message_build() failed: %s\n", error);
					return status;
				}
			}
		}
	}
	return TSS_OK;
}
void clear_buffers(TssBuffer buffers[], size_t count)
{
	for(size_t i=0; i<count; i++)
	{
		tss_buffer_free(&buffers[i]);
		buffers[i]=(TssBuffer){.data=NULL, .len=0};
	}
}
bool all_complete(const bool complete[], size_t party_count)
{
	for(size_t party=0; party<party_count; party++)
	{
		if(!complete[party])
		{
			return false;
		}
	}
	return true;
}
void print_buffer_hex(const char *label, const TssBuffer *buffer)
{
	printf("%s (%zu bytes):\n", label, buffer->len);
	for(size_t i=0; i<buffer->len; i++)
	{
		printf("%02x", buffer->data[i]);
		if((i + 1) % 32 == 0)
		{
			printf("\n");
		}
	}
	if(buffer->len % 32 != 0)
	{
		printf("\n");
	}
}
int main(void)
{
	FILE *fp=fopen("keys/pub.pem.hash", "rb");
	uint8_t hash[32];
	fread(hash, 1, sizeof(hash), fp);
	fclose(fp);
	for(size_t i=0; i<sizeof(hash); i++)
	{
		printf("%02x", hash[i]);
	}
	printf("\n");
	const size_t threshold=3;
	TssStatus status;
	TssHandle sessions[threshold];
	for(size_t i=0; i<threshold; i++)
	{
		sessions[i]=0;
	}
	TssBuffer outbound[threshold];
	for(size_t i=0; i<threshold; i++)
	{
		outbound[i]=(TssBuffer){.data=NULL, .len=0};
	}
	TssBuffer inbound[threshold];
	for(size_t i=0; i<threshold; i++)
	{
		inbound[i]=(TssBuffer){.data=NULL, .len=0};
	}
	TssHandle key_shares[threshold];
	for(size_t i=0; i<threshold; i++)
	{
		key_shares[i]=0;
	}
	bool complete[threshold];
	for(size_t i=0; i<threshold; i++)
	{
		complete[i]=false;
	}
	TssBuffer signatures[threshold];
	for(size_t i=0; i<threshold; i++)
	{
		signatures[i]=(TssBuffer){.data=NULL, .len=0};
	}
	const uint8_t session_id[]="test-sign";
	const size_t session_id_len=sizeof(session_id)-1;
	status=tss_init(0);
	if(status!=TSS_OK)
	{
		uint8_t error[1024];
		tss_last_error_copy(error, sizeof(error));
		fprintf(stderr, "tss_init() failed: %s\n", error);
		return 1;
	}
	printf("tss_version(): %s\n", tss_version());
	for(size_t i=0; i<threshold; i++)
	{
		TssBuffer share=(TssBuffer){.data=NULL, .len=0};
		char path[128];
		snprintf(path, sizeof(path), "keys/party-%zu-private.share", i+1);
		fp=fopen(path, "rb");
		fseek(fp, 0, SEEK_END);
		long len=ftell(fp);
		fseek(fp, 0, SEEK_SET);
		share.data=malloc(len);
		share.len=fread(share.data, 1, len, fp);
		fclose(fp);
		printf("share %zu: %zu bytes\n", i+1, share.len);
		status=tss_handle_import(
			share.data,
			share.len,
			7,
			&key_shares[i]);
		if(status!=TSS_OK)
		{
			uint8_t error[1024];
			tss_last_error_copy(error, sizeof(error));
			fprintf(stderr,
				"tss_handle_import() failed for share %zu: %s\n",
				i+1,
				error);
			return 1;
		}
		tss_buffer_free(&share);
		printf("share %zu imported: handle=%llu\n",
			i+1,
			(unsigned long long)key_shares[i]);
		uint16_t id;
		status=tss_handle_identifier(key_shares[i], &id);
		if(status!=TSS_OK)
		{
			uint8_t error[1024];
			tss_last_error_copy(error, sizeof(error));
			fprintf(stderr,
				"tss_handle_identifier() failed: %s\n",
				error);
			return 1;
		}
		printf("share %zu: participant id=%u\n", i+1, id);
	}
	status=phase_new(hash, session_id, session_id_len, key_shares, sessions, outbound, threshold);
	if(status!=TSS_OK)
	{
		fprintf(stderr, "phase_new() failed\n");
		return 1;
	}
	while(!all_complete(complete, threshold))
	{
		printf("simulate_traffic ");
		clear_buffers(inbound, threshold);
		status=simulate_traffic(outbound, inbound, threshold);
		if(status!=TSS_OK)
		{
			uint8_t error[1024];
			tss_last_error_copy(error, sizeof(error));
			fprintf(stderr, "simulate_traffic() failed: %s\n", error);
			return 1;
		}
		clear_buffers(outbound, threshold);
		printf("done\n");
		for(size_t party=0; party<threshold; party++)
		{
			TssSlice slice={.data=inbound[party].data, .len=inbound[party].len};
			size_t count=tss_message_count(slice);
			printf("party %zu inbound: %zu messages, %zu bytes\n", party+1, count, inbound[party].len);
			for(size_t i=0; i<count; i++)
			{
				uint16_t from;
				uint16_t to;
				TssSlice message;
				status=tss_message_at(slice, i, &from, &to, &message);
				if(status!=TSS_OK)
				{
					uint8_t error[1024];
					tss_last_error_copy(error, sizeof(error));
					fprintf(stderr, "tss_message_at() failed: %s\n", error);
					return 1;
				}
				printf("message %zu: from=%u to=%u payload=%zu bytes\n", i, from, to, message.len);
			}
		}
		for(size_t party_id=1; party_id<=threshold; party_id++)
		{
			status=phase_next(sessions, inbound, outbound, complete, signatures, party_id);
			if(status!=TSS_OK)
			{
				uint8_t error[1024];
				tss_last_error_copy(error, sizeof(error));
				fprintf(stderr, "phase_next() failed: %s\n", error);
				return 1;
			}
		}
		for(size_t party=0; party<threshold; party++)
		{
			TssSlice slice={.data=outbound[party].data, .len=outbound[party].len};
			size_t count=tss_message_count(slice);
			printf("party %zu outbound: %zu messages, %zu bytes\n", party+1, count, outbound[party].len);
			for(size_t i=0; i<count; i++)
			{
				uint16_t from;
				uint16_t to;
				TssSlice message;
				status=tss_message_at(slice, i, &from, &to, &message);
				if(status!=TSS_OK)
				{
					uint8_t error[1024];
					tss_last_error_copy(error, sizeof(error));
					fprintf(stderr, "tss_message_at() failed: %s\n", error);
					return 1;
				}
				printf("message %zu: from=%u to=%u payload=%zu bytes\n", i, from, to, message.len);
			}
		}
	}
	printf("\nSigning complete.\n");
	for(size_t i=0; i<threshold; i++)
	{
		printf("party %zu: complete=%s, signature=%zu bytes\n",
			i + 1,
			complete[i] ? "yes" : "no",
			signatures[i].len);
		if(signatures[i].len != 0)
		{
			print_buffer_hex("signature", &signatures[i]);
		}
	}
	for(size_t i=0; i<threshold; i++)
	{
		tss_buffer_free(&signatures[i]);
		tss_handle_free(key_shares[i]);
		tss_buffer_free(&inbound[i]);
		tss_buffer_free(&outbound[i]);
		tss_session_free(sessions[i]);
	}
	return 0;
}
