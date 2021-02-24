#include "StoreOCalls.h"

crust::Log *p_log = crust::Log::get_instance();

/**
 * @description: Get real path by type
 * @param path (in) -> Pointer to path
 * @param type -> Store type
 * @return: Real path
 */
std::string get_real_path_by_type(const char *path, store_type_t type)
{
    std::string r_path;
    switch (type)
    {
        case STORE_TYPE_SRD:
            r_path = Config::get_instance()->srd_path + "/" + path;
            break;
        case STORE_TYPE_SRD:
            r_path = Config::get_instance()->srd_path + "/" + path;
            break;
        case STORE_TYPE_TEMP:
            r_path = Config::get_instance()->temp_path + "/" + path;
            break;
        default:
            r_path = std::string(path);
    }

    return r_path;
}

/**
 * @description: ocall for creating directory
 * @param path (in) -> the path of directory
 * @param type -> Storage type
 * @return: Creating status
 */
crust_status_t ocall_create_dir(const char *path, store_type_t type)
{
    std::string r_path = get_real_path_by_type(path, type);

    if (access(r_path.c_str(), 0) == -1)
    {
        if (system((std::string("mkdir -p ") + r_path).c_str()) == -1)
        {
            p_log->err("Create directory:%s failed! No space or no privilege.\n", cur_path.c_str());
            return CRUST_MKDIR_FAILED;
        }
    }

    return CRUST_SUCCESS;
}

/**
 * @description: ocall for renaming directory
 * @param old_path (in) -> the old path of directory
 * @param new_path (in) -> the new path of directory
 * @param old_type -> Old path storage type
 * @param new_type -> New path storage type
 * @return: Renaming result status
 */
crust_status_t ocall_rename_dir(const char *old_path, const char *new_path, store_type_t old_type, store_type_t new_type)
{
    std::string r_old_path = get_real_path_by_type(old_path, old_type);
    std::string r_new_path = get_real_path_by_type(new_path, new_type);

    if (access(r_old_path.c_str(), 0) == -1)
    {
        return CRUST_RENAME_FILE_FAILED;
    }

    if (rename(r_old_path.c_str(), r_new_path.c_str()) == -1)
    {
        p_log->err("Rename file:%s to file:%s failed!\n", r_old_path.c_str(), r_new_path.c_str());
        return CRUST_RENAME_FILE_FAILED;
    }
        

    return CRUST_SUCCESS;
}

/**
 * @description: ocall for saving data into file
 * @param path (in) -> file path for saving
 * @param data (in) -> data for saving
 * @param len -> the length of data
 * @param type -> Storage type
 * @return: Saving result status
 */
crust_status_t ocall_save_file(const char *path, const unsigned char *data, size_t len, store_type_t type)
{
    std::string r_path = get_real_path_by_type(path, type);

    std::ofstream out;
    out.open(r_path.c_str(), std::ios::out | std::ios::binary);
    if (! out)
    {
        return CRUST_OPEN_FILE_FAILED;
    }

    crust_status_t crust_status = CRUST_SUCCESS;

    try
    {
        out.write(reinterpret_cast<const char *>(data), len);
    }
    catch (std::exception e)
    {
        crust_status = CRUST_WRITE_FILE_FAILED;
        p_log->err("Save file:%s failed! Error: %s\n", r_path.c_str(), e.what());
    }

    out.close();

    return crust_status;
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
