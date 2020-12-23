#include "StoreOcalls.h"

crust::Log *p_log = crust::Log::get_instance();

// Used to store ocall file data
uint8_t *ocall_file_data = NULL;
size_t ocall_file_data_len = 0;

/**
 * @description: ocall for creating directory
 * @param path -> the path of directory
 */
crust_status_t ocall_create_dir(const char *path)
{
    std::vector<std::string> entries;
    boost::split(entries, path, boost::is_any_of("/"));
    std::string cur_path = "";
    if (path[0] == '/')
    {
        cur_path = "/";
    }

    for (auto entry : entries)
    {
        if (entry.compare("") == 0)
            continue;

        cur_path.append(entry).append("/");
        if (access(cur_path.c_str(), 0) == -1)
        {
            if (mkdir(cur_path.c_str(), S_IRWXU) == -1)
            {
                p_log->err("Create directory:%s failed!No space or no privilege.\n", cur_path.c_str());
                return CRUST_MKDIR_FAILED;
            }
        }
    }

    return CRUST_SUCCESS;
}

/**
 * @description: ocall for renaming directory
 * @param old_path -> the old path of directory
 * @param new_path -> the new path of directory
 */
crust_status_t ocall_rename_dir(const char *old_path, const char *new_path)
{
    if (access(old_path, 0) == -1)
        return CRUST_RENAME_FILE_FAILED;

    std::vector<std::string> old_path_entry;
    std::vector<std::string> new_path_entry;
    boost::split(old_path_entry, old_path, boost::is_any_of("/"));
    boost::split(new_path_entry, new_path, boost::is_any_of("/"));

    if (old_path_entry.size() != new_path_entry.size())
    {
        p_log->err("entry size no equal!\n");
        return CRUST_RENAME_FILE_FAILED;
    }

    size_t entry_size = old_path_entry.size();
    for (size_t i = 0; i < entry_size; i++)
    {
        if (i == entry_size - 1)
        {
            if (rename(old_path, new_path) == -1)
            {
                p_log->err("Rename file:%s to file:%s failed!\n", old_path, new_path);
                return CRUST_RENAME_FILE_FAILED;
            }
        }
        else if (old_path_entry[i].compare(new_path_entry[i]) != 0)
        {
            p_log->err("entry not equal!\n");
            return CRUST_RENAME_FILE_FAILED;
        }
    }

    return CRUST_SUCCESS;
}

/**
 * @description: ocall for saving data into file
 * @param file_path -> file path for saving
 * @param data -> data for saving
 * @param len -> the length of data
 */
crust_status_t ocall_save_file(const char *file_path, const unsigned char *data, size_t len)
{
    std::ofstream out;
    out.open(file_path, std::ios::out | std::ios::binary);
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
        p_log->err("Save file:%s failed! Error: %s\n", file_path, e.what());
    }

    out.close();

    return crust_status;
}


crust_status_t ocall_delete_folder_or_file(const char *path)
{
    if (access(path, 0) != -1 && rm(path) == -1)
    {
        p_log->err("Delete '%s' error!\n", path);
        return CRUST_DELETE_FILE_FAILED;
    }

    return CRUST_SUCCESS;
}

/**
 * @description: ocall for getting file (ps: can't used by multithreading)
 * @param path -> the path of file
 * @param len -> the length of data
 * @return file data
 */
crust_status_t ocall_get_file(const char *file_path, unsigned char **p_file, size_t *len)
{
    crust_status_t crust_status = CRUST_SUCCESS;

    if (access(file_path, 0) == -1)
    {
        return CRUST_ACCESS_FILE_FAILED;
    }

    // Judge if given path is file
    struct stat s;
    if (stat (file_path, &s) == 0)
    {
        if (s.st_mode & S_IFDIR)
            return CRUST_OPEN_FILE_FAILED;
    } 

    std::ifstream in;

    in.open(file_path, std::ios::out | std::ios::binary);
    if (! in)
    {
        return CRUST_OPEN_FILE_FAILED;
    }

    in.seekg(0, std::ios::end);
    *len = in.tellg();
    in.seekg(0, std::ios::beg);

    if (*len > ocall_file_data_len)
    {
        ocall_file_data_len = 1024 * (*len / 1024) + ((*len % 1024) ? 1024 : 0);
        ocall_file_data = (uint8_t*)realloc(ocall_file_data, ocall_file_data_len);
        if (ocall_file_data == NULL)
        {
            in.close();
            return CRUST_MALLOC_FAILED;
        }
    }

    in.read(reinterpret_cast<char *>(ocall_file_data), *len);
    in.close();

    *p_file = ocall_file_data;

    return crust_status;
}
