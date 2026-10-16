#include <stdio.h>
#include <stdint.h>
#include "libtss.h"
TssStatus phase_one(int party_id, size_t user_count, size_t threshold, const uint8_t *session_id, size_t session_id_len, TssHandle sessions[], TssBuffer messages[])
{
	size_t index=party_id-1;
	TssStatus status=tss_dkg_new(7, party_id, user_count, threshold, session_id, session_id_len, &sessions[index], &messages[index]);
	if(status!=TSS_OK)
	{
		uint8_t error[1024];
		tss_last_error_copy(error, sizeof(error));
		fprintf(stderr, "tss_dkg_new() failed for party %d: %s\n", party_id, error);
		return status;
	}
	printf("dkg session %d created\n", party_id);
	printf("session handle: %llu\n", (unsigned long long)sessions[index]);
	printf("initial message bytes: %zu\n", messages[index].len);
	TssSlice messages_slice={.data=messages[index].data,.len=messages[index].len};
	size_t messages_count=tss_message_count(messages_slice);
	printf("initial message count: %zu\n", messages_count);
	for(size_t i=0; i<messages_count; i++)
	{
		uint16_t from;
		uint16_t to;
		TssSlice message;
		status=tss_message_at(messages_slice, i, &from, &to, &message);
		if(status!=TSS_OK)
		{
			uint8_t error[1024];
			tss_last_error_copy(error, sizeof(error));
			fprintf(stderr, "tss_message_at() failed: %s\n", error);
			return status;
		}
		printf("message %zu: from=%u to=%u payload=%zu bytes\n", i, from, to, message.len);
	}
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
TssStatus phase_next(size_t party_id, TssHandle sessions[], TssBuffer inbound[], TssHandle key_shares[], TssBuffer pubkey_packages[], TssBuffer outbound[], bool complete[])
{
	size_t index=party_id-1;
	TssSlice inbound_slice={.data=inbound[index].data, .len=inbound[index].len};
	TssStatus status=tss_dkg_next(sessions[index], inbound_slice, &key_shares[index], &pubkey_packages[index], &outbound[index], &complete[index]);
	if(status!=TSS_OK)
	{
		uint8_t error[1024];
		tss_last_error_copy(error, sizeof(error));
		fprintf(stderr, "tss_dkg_next() failed: %s\n", error);
		return status;
	}
	printf("dkg next for party %zu: complete=%s, outbound=%zu bytes\n", party_id, complete[index]?"yes":"no", outbound[index].len);
	return TSS_OK;
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
TssStatus extract_key_material(
	TssHandle key_share,
	int party_id,
	const char *directory)
{
	char private_path[256];
	char public_path[256];
	snprintf(private_path, sizeof(private_path),
		"%s/party-%d-private.share", directory, party_id);
	snprintf(public_path, sizeof(public_path),
		"%s/party-%d-public.key", directory, party_id);
	TssBuffer private_share={.data=NULL, .len=0};
	TssBuffer public_key={.data=NULL, .len=0};
	TssStatus status=tss_handle_export(key_share, &private_share);
	if(status!=TSS_OK)
	{
		uint8_t error[1024];
		tss_last_error_copy(error, sizeof(error));
		fprintf(stderr,
			"tss_handle_export() failed for party %d: %s\n",
			party_id, error);
		return status;
	}
	status=tss_handle_group_key(key_share, &public_key);
	if(status!=TSS_OK)
	{
		uint8_t error[1024];
		tss_last_error_copy(error, sizeof(error));
		fprintf(stderr,
			"tss_handle_group_key() failed for party %d: %s\n",
			party_id, error);
		tss_buffer_free(&private_share);
		return status;
	}
	FILE *fp=fopen(private_path, "wb");
	if(fp==NULL)
	{
		perror(private_path);
		tss_buffer_free(&private_share);
		tss_buffer_free(&public_key);
		return TSS_ERR_INTERNAL_PANIC;
	}
	if(fwrite(private_share.data, 1, private_share.len, fp)!=private_share.len)
	{
		perror(private_path);
		fclose(fp);
		tss_buffer_free(&private_share);
		tss_buffer_free(&public_key);
		return TSS_ERR_INTERNAL_PANIC;
	}
	fclose(fp);
	fp=fopen(public_path, "wb");
	if(fp==NULL)
	{
		perror(public_path);
		tss_buffer_free(&private_share);
		tss_buffer_free(&public_key);
		return TSS_ERR_INTERNAL_PANIC;
	}
	if(fwrite(public_key.data, 1, public_key.len, fp)!=public_key.len)
	{
		perror(public_path);
		fclose(fp);
		tss_buffer_free(&private_share);
		tss_buffer_free(&public_key);
		return TSS_ERR_INTERNAL_PANIC;
	}
	fclose(fp);
	printf("party %d key material:\n", party_id);
	printf("  private share: %s (%zu bytes)\n",
		private_path, private_share.len);
	printf("  public key:    %s (%zu bytes)\n",
		public_path, public_key.len);
	tss_buffer_free(&private_share);
	tss_buffer_free(&public_key);
	return TSS_OK;
}
int main(void)
{
	const size_t user_count=5;
	const size_t threshold=3;
	TssStatus status;
	TssHandle sessions[user_count];
	for(size_t i=0; i<user_count; i++)
	{
		sessions[i]=0;
	}
	TssBuffer outbound[user_count];
	for(size_t i=0; i<user_count; i++)
	{
		outbound[i]=(TssBuffer){.data=NULL, .len=0};
	}
	TssBuffer inbound[user_count];
	for(size_t i=0; i<user_count; i++)
	{
		inbound[i]=(TssBuffer){.data=NULL, .len=0};
	}
	TssHandle key_shares[user_count];
	for(size_t i=0; i<user_count; i++)
	{
		key_shares[i]=0;
	}
	TssBuffer pubkey_packages[user_count];
	for(size_t i=0; i<user_count; i++)
	{
		pubkey_packages[i]=(TssBuffer){.data=NULL, .len=0};
	}
	bool complete[user_count];
	for(size_t i=0; i<user_count; i++)
	{
		complete[i]=false;
	}
	const uint8_t session_id[]="test-dkg";
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
	for(size_t party_id=1; party_id<=user_count; party_id++)
	{
		status=phase_one(party_id, user_count, threshold, session_id, session_id_len, sessions, outbound);
		if(status!=TSS_OK)
		{
			uint8_t error[1024];
			tss_last_error_copy(error, sizeof(error));
			fprintf(stderr, "phase_one() failed: %s\n", error);
			return 1;
		}
	}
	while(!all_complete(complete, user_count))
	{
		printf("simulate_traffic ");
		clear_buffers(inbound, user_count);
		status=simulate_traffic(outbound, inbound, user_count);
		if(status!=TSS_OK)
		{
			uint8_t error[1024];
			tss_last_error_copy(error, sizeof(error));
			fprintf(stderr, "simulate_traffic() failed: %s\n", error);
			return 1;
		}
		clear_buffers(outbound, user_count);
		printf("done\n");
		for(size_t party=0; party<user_count; party++)
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
		for(size_t party_id=1; party_id<=user_count; party_id++)
		{
			status=phase_next(party_id, sessions, inbound, key_shares, pubkey_packages, outbound, complete);
			if(status!=TSS_OK)
			{
				uint8_t error[1024];
				tss_last_error_copy(error, sizeof(error));
				fprintf(stderr, "phase_next() failed: %s\n", error);
				return 1;
			}
		}
		for(size_t party=0; party<user_count; party++)
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
	printf("\nDKG complete. Extracting key material...\n");
	for(size_t party_id=1; party_id<=user_count; party_id++)
	{
		status=extract_key_material(
			key_shares[party_id-1],
			(int)party_id,
			"keys");
		if(status!=TSS_OK)
		{
			uint8_t error[1024];
			tss_last_error_copy(error, sizeof(error));
			fprintf(stderr,
				"extract_key_material() failed for party %zu: %s\n",
				party_id, error);
			return 1;
		}
	}
	for(size_t i=0; i<user_count; i++)
	{
		tss_buffer_free(&pubkey_packages[i]);
		tss_handle_free(key_shares[i]);
		tss_buffer_free(&inbound[i]);
		tss_buffer_free(&outbound[i]);
		tss_session_free(sessions[i]);
	}
	return 0;
}
