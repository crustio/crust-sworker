#include "StoreOCalls.h"

crust::Log *p_log = crust::Log::get_instance();

/**
 * @description: ocall for creating directory
 * @param path (in) -> the path of directory
 * @param type -> Storage type
 * @return: Creating status
 */
crust_status_t ocall_create_dir(const char *path, store_type_t type)
{
    std::string r_path = get_real_path_by_type(path, type);

    return create_directory(r_path);
}

/**
 * @description: ocall for renaming directory
 * @param old_path (in) -> the old path of directory
 * @param new_path (in) -> the new path of directory
 * @param type -> File storage type
 * @return: Renaming result status
 */
crust_status_t ocall_rename_dir(const char *old_path, const char *new_path, store_type_t type)
{
    std::string r_old_path = get_real_path_by_type(old_path, type);
    std::string r_new_path = get_real_path_by_type(new_path, type);

    return rename_dir(r_old_path, r_new_path);
}

/**
 * @description: ocall for saving data into file
 * @param path (in) -> file path for saving
 * @param data (in) -> data for saving
 * @param data_size -> the length of data
 * @param type -> Storage type
 * @return: Saving result status
 */
crust_status_t ocall_save_file(const char *path, const uint8_t *data, size_t data_size, store_type_t type)
{
    std::string r_path = get_real_path_by_type(path, type);

    return save_file(r_path.c_str(), data, data_size);
}

/**
 * @description: Delete folder or file
 * @param path (in) -> To be deleted path
 * @param type -> Storage type
 * @return: Saving result status
 */
crust_status_t ocall_delete_folder_or_file(const char *path, store_type_t type)
{
    std::string r_path = get_real_path_by_type(path, type);

    if (access(r_path.c_str(), 0) != -1 && rm(r_path.c_str()) == -1)
    {
        p_log->err("Delete '%s' error!\n", r_path.c_str());
        return CRUST_DELETE_FILE_FAILED;
    }

    return CRUST_SUCCESS;
}

/**
 * @description: ocall for getting file (ps: can't used by multithreading)
 * @param path (in) -> the path of file
 * @param p_file (out) -> Pointer to pointer file data
 * @param len (out) -> the length of data
 * @param type -> Storage type
 * @return file data
 */
crust_status_t ocall_get_file(const char *path, unsigned char **p_file, size_t *len, store_type_t type)
{
    std::string r_path = get_real_path_by_type(path, type);

    return get_file(r_path.c_str(), p_file, len);
}

/**
 * @description: Set srd information
 * @param data (in) -> Pointer to srd info data
 * @param data_size -> Srd info data size
 */
void ocall_set_srd_info(const uint8_t *data, size_t data_size)
{
    EnclaveData::get_instance()->set_srd_info(data, data_size);
}
