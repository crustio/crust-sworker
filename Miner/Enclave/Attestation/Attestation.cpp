#include "Attestation.h"
#include "EUtils.h"

extern ecc_key_pair id_key_pair;

ipc_status_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity);

/**
 * @description: Create a session with monitor enclave
 * @return: ipc status
 * */
ipc_status_t attest_session_starter()
{
    sgx_dh_msg1_t dh_msg1;            //Diffie-Hellman Message 1
    sgx_key_128bit_t dh_aek;          // Session Key
    sgx_dh_msg2_t dh_msg2;            //Diffie-Hellman Message 2
    sgx_dh_msg3_t dh_msg3;            //Diffie-Hellman Message 3
    ipc_status_t ipc_status;
    sgx_status_t status = SGX_SUCCESS;
    sgx_dh_session_t sgx_dh_session;
    sgx_dh_session_enclave_identity_t responder_identity;
    sgx_aes_gcm_data_t* req_message;
    const uint8_t* plaintext;
    plaintext = (const uint8_t*)(" ");
    uint32_t plaintext_length;
    plaintext_length = 0;

    //Allocate memory for the AES-GCM request message
    req_message = (sgx_aes_gcm_data_t*)malloc(sizeof(sgx_aes_gcm_data_t)+sizeof(ecc_key_pair));
    if(!req_message)
    {
        return MALLOC_ERROR;
    }

    memset(req_message,0,sizeof(sgx_aes_gcm_data_t)+sizeof(ecc_key_pair));
    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    memset(&dh_msg1, 0, sizeof(sgx_dh_msg1_t));
    memset(&dh_msg2, 0, sizeof(sgx_dh_msg2_t));
    memset(&dh_msg3, 0, sizeof(sgx_dh_msg3_t));

    //Set the payload size to data to encrypt length
    req_message->payload_size = sizeof(ecc_key_pair);
    memcpy(req_message->reserved,"0123456789",10);

    //Intialize the session as a session initiator
    status = sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
        return IPC_SGX_ERROR;
    }

    //Ocall to request for a session with the destination enclave and obtain session id and Message 1 if successful
    status = ocall_send_request_recv_msg1(&ipc_status, &dh_msg1);
    if (status == SGX_SUCCESS)
    {
        if (ipc_status != IPC_SUCCESS)
            return ipc_status;
    }
    else
    {
        return ATTESTATION_SE_ERROR;
    }
    //Process the message 1 obtained from desination enclave and generate message 2
    status = sgx_dh_initiator_proc_msg1(&dh_msg1, &dh_msg2, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
         return IPC_SGX_ERROR;
    }

    //Send Message 2 to Destination Enclave and get Message 3 in return
    status = ocall_send_msg2_recv_msg3(&ipc_status, &dh_msg2, &dh_msg3);
    if (status == SGX_SUCCESS)
    {
        if (ipc_status != IPC_SUCCESS)
            return ipc_status;
    }
    else
    {
        return ATTESTATION_SE_ERROR;
    }

    //Process Message 3 obtained from the destination enclave
    status = sgx_dh_initiator_proc_msg3(&dh_msg3, &sgx_dh_session, &dh_aek, &responder_identity);
    if(SGX_SUCCESS != status)
    {
        return IPC_SGX_ERROR;
    }

    // Verify the identity of the destination enclave
    if(verify_peer_enclave_trust(&responder_identity) != IPC_SUCCESS)
    {
        return INVALID_SESSION;
    }
    //eprintf("[enclave]===========payload size:%d\n", req_message->payload_size);

    // Send key pair to monitor process tee
    status = sgx_rijndael128GCM_encrypt(&dh_aek, (uint8_t*)&id_key_pair, sizeof(ecc_key_pair),
                reinterpret_cast<uint8_t *>(&(req_message->payload)),
                reinterpret_cast<uint8_t *>(&(req_message->reserved)),
                sizeof(req_message->reserved), plaintext, plaintext_length,
                &(req_message->payload_tag));

    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(req_message);
        return IPC_SGX_ERROR;
    }
    //eprintf("[enclave]===========received data:%s\n", hexstring(&id_key_pair, sizeof(ecc_key_pair)));

    status = ocall_send_keypair(&ipc_status, req_message, sizeof(sgx_aes_gcm_data_t)+sizeof(ecc_key_pair));
    if(SGX_SUCCESS == status)
    {
        if(IPC_SUCCESS != ipc_status)
        {
            return ipc_status;
        }
    }
    else
    {
        SAFE_FREE(req_message);
        return IPC_SGX_ERROR;
    }

    return IPC_SUCCESS;
}

/**
 * @description: Handle the request from worker enclave
 * @return: ipc status
 * */
ipc_status_t attest_session_receiver()
{
    sgx_dh_session_t sgx_dh_session;
    sgx_status_t status = SGX_SUCCESS;
    char* request = (char*)malloc(20);
    sgx_key_128bit_t dh_aek;          // Session Key
    sgx_dh_msg1_t dh_msg1;
    sgx_dh_msg2_t dh_msg2;
    sgx_dh_msg3_t dh_msg3;
    sgx_dh_session_enclave_identity_t initiator_identity;
    ipc_status_t ipc_status;
    sgx_aes_gcm_data_t *req_message;
    req_message = (sgx_aes_gcm_data_t*)malloc(sizeof(sgx_aes_gcm_data_t)+sizeof(ecc_key_pair));
    uint32_t plain_text_offset;
    uint32_t plaintext_length = 0;
    uint32_t decrypted_data_length;
    uint8_t *decrypted_data;

    memset(req_message, 0, sizeof(sgx_aes_gcm_data_t)+sizeof(ecc_key_pair));
    memset(request, 0, 20);
    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    memset(&dh_msg1, 0, sizeof(sgx_dh_msg1_t));
    memset(&dh_msg2, 0, sizeof(sgx_dh_msg2_t));
    memset(&dh_msg3, 0, sizeof(sgx_dh_msg3_t));

    status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
        return IPC_SGX_ERROR;
    }

    // Waiting for session request
    status = ocall_recv_session_request(&ipc_status, request);
    if(SGX_SUCCESS == status)
    {
        if(IPC_SUCCESS != ipc_status)
        {
            return ipc_status;
        }
        if(strcmp(request, "SessionRequest") != 0)
        {
            return ATTESTATION_BADREQUEST;
        }
    }
    else
    {
        return IPC_SGX_ERROR;
    }

    //Generate Message1 that will be returned to Source Enclave
    status = sgx_dh_responder_gen_msg1((sgx_dh_msg1_t*)&dh_msg1, &sgx_dh_session);
    if(SGX_SUCCESS != status)
    {
        return IPC_SGX_ERROR;
    }

    // Send Message1 and receive Message2 from worker
    status = ocall_send_msg1_recv_msg2(&ipc_status, &dh_msg1, &dh_msg2);
    if(SGX_SUCCESS == status)
    {
        if(IPC_SUCCESS != ipc_status)
        {
            return ipc_status;
        }
    }
    else
    {
        return IPC_SGX_ERROR;
    }

    do
    {
        memcpy(&sgx_dh_session, &sgx_dh_session, sizeof(sgx_dh_session_t));

        dh_msg3.msg3_body.additional_prop_length = 0;
        // Process message 2 from source enclave and obtain message 3
        sgx_status_t se_ret = sgx_dh_responder_proc_msg2(&dh_msg2,
                                                       &dh_msg3,
                                                       &sgx_dh_session,
                                                       &dh_aek,
                                                       &initiator_identity);
        if(SGX_SUCCESS != se_ret)
        {
            status = se_ret;
            break;
        }

        // Send Message3 to worker
        status = ocall_send_msg3(&ipc_status, &dh_msg3);
        if(SGX_SUCCESS == status)
        {
            if(IPC_SUCCESS != ipc_status)
            {
                return ipc_status;
            }
        }
        else
        {
            return IPC_SGX_ERROR;
        }

        //Verify source enclave's trust
        if(verify_peer_enclave_trust(&initiator_identity) != IPC_SUCCESS)
        {
            return INVALID_SESSION;
        }

        // Receive tee key pair from worker process
        status = ocall_recv_keypair(&ipc_status, req_message, sizeof(sgx_aes_gcm_data_t)+sizeof(ecc_key_pair));
        if(SGX_SUCCESS == status)
        {
            if(IPC_SUCCESS != ipc_status)
            {
                return ipc_status;
            }
        }
        else
        {
            return IPC_TRANSFER_ERROR;
        }

        plain_text_offset = req_message->payload_size;
        decrypted_data_length = req_message->payload_size;
        //eprintf("[enclave]==========payload size:%d\n", decrypted_data_length);
        decrypted_data = (uint8_t*)malloc(decrypted_data_length);
        if(!decrypted_data)
        {
            return MALLOC_ERROR;
        }

        memset(decrypted_data, 0, decrypted_data_length);

        //Decrypt the request message payload from source enclave
        status = sgx_rijndael128GCM_decrypt(&dh_aek, req_message->payload,
                    decrypted_data_length, decrypted_data,
                    reinterpret_cast<uint8_t *>(&(req_message->reserved)),
                    sizeof(req_message->reserved), &(req_message->payload[plain_text_offset]), plaintext_length,
                    &req_message->payload_tag);
    
        if(SGX_SUCCESS != status)
        {
            SAFE_FREE(decrypted_data);
            return IPC_SGX_ERROR;
        }

        eprintf("[enclave]===========received data:%s\n",hexstring(decrypted_data, decrypted_data_length));

        memcpy(&id_key_pair, decrypted_data, sizeof(ecc_key_pair));

    } while(0);

    return IPC_SUCCESS;
}

/**
 * @description: Function that is used to verify the trust of the other enclave
 * Each enclave can have its own way verifying the peer enclave identity
 * @return: verify status
 * */
ipc_status_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity)
{
    if(!peer_enclave_identity)
    {
        return INVALID_PARAMETER_ERROR;
    }
    if(peer_enclave_identity->isv_prod_id != 0 || !(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED))
        // || peer_enclave_identity->attributes.xfrm !=3)// || peer_enclave_identity->mr_signer != xx //TODO: To be hardcoded with values to check
    {
        return ENCLAVE_TRUST_ERROR;
    }
    else
    {
        return IPC_SUCCESS;
    }
}
