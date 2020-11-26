#include "IpfsOCalls.h"

void delete_validated_tree(json::JSON &tree);

crust::Log *p_log = crust::Log::get_instance();

/**	
 * @description: Test if there is usable IPFS	
 * @return: Test result	
 */
bool ocall_ipfs_online()
{
    return Ipfs::get_instance()->online();
}

/**	
 * @description: Get block from ipfs
 * @param cid -> Ipfs content id
 * @param p_data -> Pointer to pointer to ipfs data
 * @param data_size -> Pointer to ipfs data size
 * @return: Status
 */
crust_status_t ocall_ipfs_get_block(const char *cid, uint8_t **p_data, size_t *data_size)
{
    *data_size = Ipfs::get_instance()->block_get(cid, p_data);
    if (*data_size == 0)
    {
        return CRUST_STORAGE_IPFS_BLOCK_GET_ERROR;
    }
    return CRUST_SUCCESS;
}

/**	
 * @description: Cat file
 * @param cid -> Ipfs content id
 * @param p_data -> Pointer to pointer to ipfs data
 * @param data_size -> Pointer to ipfs data size
 * @return: Status
 */
crust_status_t ocall_ipfs_cat(const char *cid, uint8_t **p_data, size_t *data_size)
{
    if (!Ipfs::get_instance()->online())
    {
        return CRUST_SERVICE_UNAVAILABLE;
    }

    *data_size = Ipfs::get_instance()->cat(cid, p_data);
    if (*data_size == 0)
    {
        return CRUST_STORAGE_IPFS_CAT_ERROR;
    }
    return CRUST_SUCCESS;
}

/**	
 * @description: Add file to ipfs
 * @param p_data -> Pointer to be added data
 * @param len -> Added data length
 * @param cid -> Pointer to returned ipfs content id
 * @return: Status
 */
crust_status_t ocall_ipfs_add(uint8_t *p_data, size_t len, char *cid, size_t /*cid_len*/)
{
    std::string cid_str = Ipfs::get_instance()->add(p_data, len);
    if (cid_str.size() == 0)
    {
        return CRUST_STORAGE_IPFS_ADD_ERROR;
    }

    memcpy(cid, cid_str.c_str(), cid_str.size());

    return CRUST_SUCCESS;
}

/**	
 * @description: Delete file
 * @param cid -> To be deleted file cid
 * @return: Status
 */
crust_status_t ocall_ipfs_del(const char *cid)
{
    crust_status_t crust_status = CRUST_SUCCESS;
    crust::DataBase *db = crust::DataBase::get_instance();
    std::string tree_str;
    if (CRUST_SUCCESS != (crust_status = db->get(cid, tree_str)))
    {
        p_log->err("Get validate tree(%s) failed! Error code:%lx\n", cid, crust_status);
        return CRUST_UNEXPECTED_ERROR;
    }

    // Delete related ipfs data
    json::JSON tree = json::JSON::Load(tree_str);
    delete_validated_tree(tree);

    return CRUST_SUCCESS;
}

/**
 * @description: Delete validated merkle tree
 * @param tree -> Reference to tree json
 */
void delete_validated_tree(json::JSON &tree)
{
    if (!tree.hasKey(MT_CID))
    {
        return;
    }

    // Delete current data
    std::string cid = tree[MT_CID].ToString();
    if (!Ipfs::get_instance()->del(cid))
    {
        p_log->warn("Cannot delete sealed block(cid:%s)!\n", cid.c_str());
    }

    // Delete children's data
    for (int i = 0; i < tree[MT_LINKS].size(); i++)
    {
        delete_validated_tree(tree[MT_LINKS][i]);
    }
}
