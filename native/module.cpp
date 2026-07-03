#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <realm.h>
#include <realm/decimal128.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace py = pybind11;

namespace {

class NativeError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

[[noreturn]] void throw_last_error(const std::string& context)
{
    realm_error_t error{};
    if (realm_get_last_error(&error)) {
        std::string message = context + ": ";
        message += error.message ? error.message : "unknown Realm error";
        if (error.path && *error.path) {
            message += " [" + std::string(error.path) + "]";
        }
        throw NativeError(message);
    }
    throw NativeError(context + ": unknown Realm error");
}

void require(bool ok, const std::string& context)
{
    if (!ok) {
        throw_last_error(context);
    }
}

template <typename T>
struct RealmReleaser {
    void operator()(T* value) const noexcept
    {
        realm_release(value);
    }
};

template <typename T>
using RealmPtr = std::unique_ptr<T, RealmReleaser<T>>;

template <typename T>
RealmPtr<T> owned(T* value, const std::string& context)
{
    if (!value) {
        throw_last_error(context);
    }
    return RealmPtr<T>(value);
}

std::string property_type_name(realm_property_type_e type)
{
    switch (type) {
        case RLM_PROPERTY_TYPE_INT:
            return "int";
        case RLM_PROPERTY_TYPE_BOOL:
            return "bool";
        case RLM_PROPERTY_TYPE_STRING:
            return "string";
        case RLM_PROPERTY_TYPE_BINARY:
            return "binary";
        case RLM_PROPERTY_TYPE_MIXED:
            return "mixed";
        case RLM_PROPERTY_TYPE_TIMESTAMP:
            return "timestamp";
        case RLM_PROPERTY_TYPE_FLOAT:
            return "float";
        case RLM_PROPERTY_TYPE_DOUBLE:
            return "double";
        case RLM_PROPERTY_TYPE_DECIMAL128:
            return "decimal128";
        case RLM_PROPERTY_TYPE_OBJECT:
            return "object";
        case RLM_PROPERTY_TYPE_LINKING_OBJECTS:
            return "linking_objects";
        case RLM_PROPERTY_TYPE_OBJECT_ID:
            return "object_id";
        case RLM_PROPERTY_TYPE_UUID:
            return "uuid";
    }
    return "unknown";
}

std::string collection_type_name(realm_collection_type_e type)
{
    switch (type) {
        case RLM_COLLECTION_TYPE_NONE:
            return "none";
        case RLM_COLLECTION_TYPE_LIST:
            return "list";
        case RLM_COLLECTION_TYPE_SET:
            return "set";
        case RLM_COLLECTION_TYPE_DICTIONARY:
            return "dictionary";
    }
    return "unknown";
}

std::string object_id_string(const realm_object_id_t& object_id)
{
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (const auto byte : object_id.bytes) {
        stream << std::setw(2) << static_cast<unsigned>(byte);
    }
    return stream.str();
}

std::string uuid_string(const realm_uuid_t& uuid)
{
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (std::size_t index = 0; index < sizeof(uuid.bytes); ++index) {
        if (index == 4 || index == 6 || index == 8 || index == 10) {
            stream << '-';
        }
        stream << std::setw(2) << static_cast<unsigned>(uuid.bytes[index]);
    }
    return stream.str();
}

std::string decimal_string(const realm_decimal128_t& value)
{
    realm::Decimal128::Bid128 raw{{value.w[0], value.w[1]}};
    return realm::Decimal128(raw).to_string();
}

struct NativeLink {
    realm_class_key_t table_key;
    realm_object_key_t object_key;
};

struct NativeTimestamp {
    std::int64_t seconds;
    std::int32_t nanoseconds;
};

struct NativeObjectId {
    std::string value;
};

struct NativeDecimal128 {
    std::string value;
};

struct PropertyMeta {
    std::string name;
    std::string public_name;
    std::string link_target;
    std::string link_origin_property_name;
    realm_property_type_e type;
    realm_collection_type_e collection_type;
    realm_property_key_t key;
    int flags;
};

struct ClassMeta {
    std::string name;
    std::string primary_key;
    realm_class_key_t key;
    int flags;
    std::vector<PropertyMeta> properties;
};

class NativeRealm;

class NativeResults {
public:
    NativeResults(std::shared_ptr<NativeRealm> realm, realm_results_t* results);

    std::size_t size() const;
    py::dict get(std::int64_t index) const;

private:
    std::shared_ptr<NativeRealm> m_realm;
    RealmPtr<realm_results_t> m_results;
};

class NativeRealm : public std::enable_shared_from_this<NativeRealm> {
public:
    NativeRealm(std::string path, py::bytes key)
        : m_path(std::move(path))
    {
        std::string key_data = key;
        if (!key_data.empty() && key_data.size() != 64) {
            throw py::value_error("Realm encryption keys must contain exactly 64 bytes");
        }

        auto config = owned(realm_config_new(), "create Realm configuration");
        realm_config_set_path(config.get(), m_path.c_str());
        realm_config_set_schema_mode(config.get(), RLM_SCHEMA_MODE_IMMUTABLE);
        realm_config_set_disable_format_upgrade(config.get(), true);
        realm_config_set_automatic_change_notifications(config.get(), false);
        realm_config_set_cached(config.get(), false);
        if (!key_data.empty()) {
            require(
                realm_config_set_encryption_key(
                    config.get(), reinterpret_cast<const std::uint8_t*>(key_data.data()), key_data.size()),
                "set Realm encryption key");
        }

        m_realm = owned(realm_open(config.get()), "open Realm immutably");
        load_schema();
    }

    const std::string& path() const noexcept
    {
        return m_path;
    }

    std::string core_version() const
    {
        return realm_get_library_version();
    }

    void close()
    {
        if (m_realm && !realm_is_closed(m_realm.get())) {
            require(realm_close(m_realm.get()), "close Realm");
        }
    }

    py::list schema() const
    {
        py::list classes;
        for (const auto& class_meta : m_classes) {
            py::dict class_info;
            class_info["name"] = class_meta.name;
            class_info["key"] = class_meta.key;
            class_info["primary_key"] =
                class_meta.primary_key.empty() ? py::none() : py::cast(class_meta.primary_key);
            class_info["embedded"] = (class_meta.flags & RLM_CLASS_MASK) == RLM_CLASS_EMBEDDED;
            class_info["asymmetric"] = (class_meta.flags & RLM_CLASS_MASK) == RLM_CLASS_ASYMMETRIC;

            py::list properties;
            for (const auto& property : class_meta.properties) {
                py::dict property_info;
                property_info["name"] = property.name;
                property_info["public_name"] =
                    property.public_name.empty() ? py::none() : py::cast(property.public_name);
                property_info["key"] = property.key;
                property_info["type"] = property_type_name(property.type);
                property_info["collection"] = collection_type_name(property.collection_type);
                property_info["nullable"] = bool(property.flags & RLM_PROPERTY_NULLABLE);
                property_info["primary_key"] = bool(property.flags & RLM_PROPERTY_PRIMARY_KEY);
                property_info["indexed"] = bool(property.flags & RLM_PROPERTY_INDEXED);
                property_info["link_target"] =
                    property.link_target.empty() ? py::none() : py::cast(property.link_target);
                property_info["link_origin_property"] = property.link_origin_property_name.empty()
                    ? py::none()
                    : py::cast(property.link_origin_property_name);
                properties.append(std::move(property_info));
            }
            class_info["properties"] = std::move(properties);
            classes.append(std::move(class_info));
        }
        return classes;
    }

    std::vector<std::string> table_names() const
    {
        std::vector<std::string> names;
        names.reserve(m_classes.size());
        for (const auto& class_meta : m_classes) {
            names.push_back(class_meta.name);
        }
        return names;
    }

    std::size_t count(const std::string& table_name) const
    {
        std::size_t result = 0;
        require(
            realm_get_num_objects(m_realm.get(), find_class(table_name).key, &result),
            "count objects in table '" + table_name + "'");
        return result;
    }

    std::shared_ptr<NativeResults> all(const std::string& table_name)
    {
        const auto& class_meta = find_class(table_name);
        auto* results = realm_object_find_all(m_realm.get(), class_meta.key);
        if (!results) {
            throw_last_error("read objects from table '" + table_name + "'");
        }
        return std::make_shared<NativeResults>(shared_from_this(), results);
    }

    std::shared_ptr<NativeResults>
    query(const std::string& table_name, const std::string& query_text, const py::args& args)
    {
        const auto& class_meta = find_class(table_name);
        std::vector<QueryValue> values;
        values.reserve(args.size());
        for (const auto& arg : args) {
            values.push_back(query_value(arg));
        }

        std::vector<realm_query_arg_t> query_args;
        query_args.reserve(values.size());
        for (auto& value : values) {
            if (value.value.type == RLM_TYPE_STRING) {
                value.value.string = {
                    value.string_storage.data(),
                    value.string_storage.size(),
                };
            }
            else if (value.value.type == RLM_TYPE_BINARY) {
                value.value.binary = {
                    value.binary_storage.data(),
                    value.binary_storage.size(),
                };
            }
            query_args.push_back(realm_query_arg_t{1, false, &value.value});
        }

        auto query = owned(
            realm_query_parse(
                m_realm.get(), class_meta.key, query_text.c_str(), query_args.size(), query_args.data()),
            "parse Realm query");
        auto* results = realm_query_find_all(query.get());
        if (!results) {
            throw_last_error("execute Realm query");
        }
        return std::make_shared<NativeResults>(shared_from_this(), results);
    }

    py::dict record(realm_class_key_t table_key, realm_object_key_t object_key) const
    {
        const auto& class_meta = find_class(table_key);
        auto object = owned(
            realm_get_object(m_realm.get(), table_key, object_key),
            "read object from table '" + class_meta.name + "'");
        return object_to_dict(object.get(), class_meta);
    }

    py::dict object_to_dict(realm_object_t* object) const
    {
        return object_to_dict(object, find_class(realm_object_get_table(object)));
    }

private:
    struct QueryValue {
        realm_value_t value{};
        std::string string_storage;
        std::vector<std::uint8_t> binary_storage;
    };

    void load_schema()
    {
        std::size_t class_count = 0;
        require(
            realm_get_class_keys(m_realm.get(), nullptr, 0, &class_count),
            "read Realm class count");
        std::vector<realm_class_key_t> class_keys(class_count);
        require(
            realm_get_class_keys(m_realm.get(), class_keys.data(), class_keys.size(), &class_count),
            "read Realm class keys");

        m_classes.reserve(class_count);
        for (const auto class_key : class_keys) {
            realm_class_info_t info{};
            require(realm_get_class(m_realm.get(), class_key, &info), "read Realm class");

            ClassMeta class_meta{
                info.name ? info.name : "",
                info.primary_key ? info.primary_key : "",
                info.key,
                info.flags,
                {},
            };

            std::size_t property_count = 0;
            require(
                realm_get_class_properties(m_realm.get(), class_key, nullptr, 0, &property_count),
                "read Realm property count");
            std::vector<realm_property_info_t> properties(property_count);
            require(
                realm_get_class_properties(
                    m_realm.get(), class_key, properties.data(), properties.size(), &property_count),
                "read Realm properties");
            class_meta.properties.reserve(property_count);
            for (const auto& property : properties) {
                class_meta.properties.push_back(PropertyMeta{
                    property.name ? property.name : "",
                    property.public_name ? property.public_name : "",
                    property.link_target ? property.link_target : "",
                    property.link_origin_property_name ? property.link_origin_property_name : "",
                    property.type,
                    property.collection_type,
                    property.key,
                    property.flags,
                });
            }

            m_class_indexes.emplace(class_meta.key, m_classes.size());
            m_class_names.emplace(class_meta.name, m_classes.size());
            m_classes.push_back(std::move(class_meta));
        }
    }

    const ClassMeta& find_class(const std::string& name) const
    {
        const auto found = m_class_names.find(name);
        if (found == m_class_names.end()) {
            throw py::key_error("Realm table not found: " + name);
        }
        return m_classes[found->second];
    }

    const ClassMeta& find_class(realm_class_key_t key) const
    {
        const auto found = m_class_indexes.find(key);
        if (found == m_class_indexes.end()) {
            throw NativeError("Realm table key not found: " + std::to_string(key));
        }
        return m_classes[found->second];
    }

    py::object value_to_python(const realm_value_t& value) const
    {
        switch (value.type) {
            case RLM_TYPE_NULL:
                return py::none();
            case RLM_TYPE_INT:
                return py::int_(value.integer);
            case RLM_TYPE_BOOL:
                return py::bool_(value.boolean);
            case RLM_TYPE_STRING:
                return py::str(value.string.data, value.string.size);
            case RLM_TYPE_BINARY:
                return py::bytes(
                    reinterpret_cast<const char*>(value.binary.data), value.binary.size);
            case RLM_TYPE_TIMESTAMP:
                return py::cast(NativeTimestamp{
                    value.timestamp.seconds,
                    value.timestamp.nanoseconds,
                });
            case RLM_TYPE_FLOAT:
                return py::float_(value.fnum);
            case RLM_TYPE_DOUBLE:
                return py::float_(value.dnum);
            case RLM_TYPE_DECIMAL128:
                return py::cast(NativeDecimal128{decimal_string(value.decimal128)});
            case RLM_TYPE_OBJECT_ID:
                return py::cast(NativeObjectId{object_id_string(value.object_id)});
            case RLM_TYPE_LINK:
                return py::cast(NativeLink{value.link.target_table, value.link.target});
            case RLM_TYPE_UUID:
                return py::module_::import("uuid").attr("UUID")(uuid_string(value.uuid));
        }
        throw NativeError("unsupported Realm value type");
    }

    py::list list_to_python(realm_object_t* object, realm_property_key_t property_key) const
    {
        auto list = owned(realm_get_list(object, property_key), "read Realm list");
        std::size_t size = 0;
        require(realm_list_size(list.get(), &size), "read Realm list size");
        py::list result;
        for (std::size_t index = 0; index < size; ++index) {
            realm_value_t value{};
            require(realm_list_get(list.get(), index, &value), "read Realm list value");
            result.append(value_to_python(value));
        }
        return result;
    }

    py::list set_to_python(realm_object_t* object, realm_property_key_t property_key) const
    {
        auto set = owned(realm_get_set(object, property_key), "read Realm set");
        std::size_t size = 0;
        require(realm_set_size(set.get(), &size), "read Realm set size");
        py::list result;
        for (std::size_t index = 0; index < size; ++index) {
            realm_value_t value{};
            require(realm_set_get(set.get(), index, &value), "read Realm set value");
            result.append(value_to_python(value));
        }
        return result;
    }

    py::dict dictionary_to_python(realm_object_t* object, realm_property_key_t property_key) const
    {
        auto dictionary =
            owned(realm_get_dictionary(object, property_key), "read Realm dictionary");
        std::size_t size = 0;
        require(realm_dictionary_size(dictionary.get(), &size), "read Realm dictionary size");
        py::dict result;
        for (std::size_t index = 0; index < size; ++index) {
            realm_value_t key{};
            realm_value_t value{};
            require(
                realm_dictionary_get(dictionary.get(), index, &key, &value),
                "read Realm dictionary value");
            result[value_to_python(key)] = value_to_python(value);
        }
        return result;
    }

    py::dict object_to_dict(realm_object_t* object, const ClassMeta& class_meta) const
    {
        py::dict result;
        result["__table_key__"] = class_meta.key;
        result["__object_key__"] = realm_object_get_key(object);
        for (const auto& property : class_meta.properties) {
            if (property.type == RLM_PROPERTY_TYPE_LINKING_OBJECTS) {
                continue;
            }
            switch (property.collection_type) {
                case RLM_COLLECTION_TYPE_LIST:
                    result[py::str(property.name)] = list_to_python(object, property.key);
                    break;
                case RLM_COLLECTION_TYPE_SET:
                    result[py::str(property.name)] = set_to_python(object, property.key);
                    break;
                case RLM_COLLECTION_TYPE_DICTIONARY:
                    result[py::str(property.name)] = dictionary_to_python(object, property.key);
                    break;
                case RLM_COLLECTION_TYPE_NONE: {
                    realm_value_t value{};
                    require(
                        realm_get_value(object, property.key, &value),
                        "read property '" + property.name + "'");
                    result[py::str(property.name)] = value_to_python(value);
                    break;
                }
            }
        }
        return result;
    }

    static QueryValue query_value(const py::handle& input)
    {
        QueryValue output;
        if (input.is_none()) {
            output.value.type = RLM_TYPE_NULL;
        }
        else if (py::isinstance<py::bool_>(input)) {
            output.value.type = RLM_TYPE_BOOL;
            output.value.boolean = py::cast<bool>(input);
        }
        else if (py::isinstance<py::int_>(input)) {
            output.value.type = RLM_TYPE_INT;
            output.value.integer = py::cast<std::int64_t>(input);
        }
        else if (py::isinstance<py::float_>(input)) {
            output.value.type = RLM_TYPE_DOUBLE;
            output.value.dnum = py::cast<double>(input);
        }
        else if (py::isinstance<py::str>(input)) {
            output.string_storage = py::cast<std::string>(input);
            output.value.type = RLM_TYPE_STRING;
            output.value.string = {
                output.string_storage.data(),
                output.string_storage.size(),
            };
        }
        else if (py::isinstance<py::bytes>(input)) {
            std::string bytes = py::cast<std::string>(input);
            output.binary_storage.assign(bytes.begin(), bytes.end());
            output.value.type = RLM_TYPE_BINARY;
            output.value.binary = {
                output.binary_storage.data(),
                output.binary_storage.size(),
            };
        }
        else {
            throw py::type_error(
                "Realm query parameters currently support None, bool, int, float, str, and bytes");
        }
        return output;
    }

    std::string m_path;
    RealmPtr<realm_t> m_realm;
    std::vector<ClassMeta> m_classes;
    std::unordered_map<std::string, std::size_t> m_class_names;
    std::unordered_map<realm_class_key_t, std::size_t> m_class_indexes;

    friend class NativeResults;
};

NativeResults::NativeResults(std::shared_ptr<NativeRealm> realm, realm_results_t* results)
    : m_realm(std::move(realm))
    , m_results(results)
{
}

std::size_t NativeResults::size() const
{
    std::size_t size = 0;
    require(realm_results_count(m_results.get(), &size), "count Realm query results");
    return size;
}

py::dict NativeResults::get(std::int64_t index) const
{
    const auto count = static_cast<std::int64_t>(size());
    if (index < 0) {
        index += count;
    }
    if (index < 0 || index >= count) {
        throw py::index_error("Realm result index out of range");
    }
    auto object = owned(
        realm_results_get_object(m_results.get(), static_cast<std::size_t>(index)),
        "read Realm query result");
    return m_realm->object_to_dict(object.get());
}

} // namespace

PYBIND11_MODULE(_native, module)
{
    module.doc() = "Read-only Realm Core bridge";

    py::register_exception<NativeError>(module, "NativeError");

    py::class_<NativeLink>(module, "NativeLink")
        .def_readonly("table_key", &NativeLink::table_key)
        .def_readonly("object_key", &NativeLink::object_key);

    py::class_<NativeTimestamp>(module, "NativeTimestamp")
        .def_readonly("seconds", &NativeTimestamp::seconds)
        .def_readonly("nanoseconds", &NativeTimestamp::nanoseconds);

    py::class_<NativeObjectId>(module, "NativeObjectId")
        .def_readonly("value", &NativeObjectId::value);

    py::class_<NativeDecimal128>(module, "NativeDecimal128")
        .def_readonly("value", &NativeDecimal128::value);

    py::class_<NativeResults, std::shared_ptr<NativeResults>>(module, "NativeResults")
        .def("__len__", &NativeResults::size)
        .def("__getitem__", &NativeResults::get);

    py::class_<NativeRealm, std::shared_ptr<NativeRealm>>(module, "NativeRealm")
        .def(py::init<std::string, py::bytes>(), py::arg("path"), py::arg("key") = py::bytes())
        .def_property_readonly("path", &NativeRealm::path)
        .def_property_readonly("core_version", &NativeRealm::core_version)
        .def("close", &NativeRealm::close)
        .def("schema", &NativeRealm::schema)
        .def("table_names", &NativeRealm::table_names)
        .def("count", &NativeRealm::count)
        .def("all", &NativeRealm::all)
        .def("query", &NativeRealm::query)
        .def("record", &NativeRealm::record);
}
