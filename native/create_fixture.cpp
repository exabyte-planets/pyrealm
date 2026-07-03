#include <realm.h>

#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>

namespace {

struct Releaser {
    void operator()(void* value) const noexcept
    {
        realm_release(value);
    }
};

template <typename T>
using RealmPtr = std::unique_ptr<T, Releaser>;

[[noreturn]] void fail(const std::string& context)
{
    realm_error_t error{};
    if (realm_get_last_error(&error) && error.message) {
        throw std::runtime_error(context + ": " + error.message);
    }
    throw std::runtime_error(context);
}

void check(bool success, const std::string& context)
{
    if (!success) {
        fail(context);
    }
}

template <typename T>
RealmPtr<T> take(T* value, const std::string& context)
{
    if (!value) {
        fail(context);
    }
    return RealmPtr<T>(value);
}

bool scheduler_is_on_thread(realm_userdata_t)
{
    return true;
}

bool scheduler_is_same_as(const void*, const void*)
{
    return true;
}

bool scheduler_can_deliver_notifications(realm_userdata_t)
{
    return false;
}

RealmPtr<realm_scheduler_t> make_scheduler()
{
    return take(
        realm_scheduler_new(
            nullptr,
            nullptr,
            nullptr,
            scheduler_is_on_thread,
            scheduler_is_same_as,
            scheduler_can_deliver_notifications),
        "create Realm scheduler");
}

realm_value_t integer(std::int64_t value)
{
    realm_value_t result{};
    result.type = RLM_TYPE_INT;
    result.integer = value;
    return result;
}

realm_value_t string(const char* value)
{
    realm_value_t result{};
    result.type = RLM_TYPE_STRING;
    result.string = {value, std::char_traits<char>::length(value)};
    return result;
}

realm_value_t link(realm_object_t* object)
{
    realm_value_t result{};
    result.type = RLM_TYPE_LINK;
    result.link = realm_object_as_link(object);
    return result;
}

realm_property_info_t property(
    const char* name,
    realm_property_type_e type,
    int flags = RLM_PROPERTY_NORMAL,
    const char* target = "")
{
    return {
        name,
        "",
        type,
        RLM_COLLECTION_TYPE_NONE,
        target,
        "",
        RLM_INVALID_PROPERTY_KEY,
        flags,
    };
}

} // namespace

int main(int argc, char** argv)
try {
    const std::string realm_path = argc > 1 ? argv[1] : "";
    const std::string key_path = argc > 2 ? argv[2] : "";
    // Realm creates side files named after its path, so a flag mistaken for a path
    // (e.g. --help) would litter the working directory with --help.lock and friends.
    if (argc != 3 || realm_path.empty() || key_path.empty() || realm_path.front() == '-'
        || key_path.front() == '-') {
        std::cerr << "usage: pyrealm_fixture_generator OUTPUT.realm OUTPUT.key\n";
        return 2;
    }
    std::array<std::uint8_t, 64> key{};
    for (std::size_t index = 0; index < key.size(); ++index) {
        key[index] = static_cast<std::uint8_t>(index);
    }

    std::ofstream key_file(key_path, std::ios::binary);
    key_file.write(reinterpret_cast<const char*>(key.data()), key.size());
    key_file.close();
    if (!key_file) {
        throw std::runtime_error("failed to write fixture key file: " + key_path);
    }

    const realm_property_info_t person_properties[] = {
        property(
            "id",
            RLM_PROPERTY_TYPE_INT,
            RLM_PROPERTY_PRIMARY_KEY | RLM_PROPERTY_INDEXED),
        property("name", RLM_PROPERTY_TYPE_STRING),
        property("age", RLM_PROPERTY_TYPE_INT),
        property("friend", RLM_PROPERTY_TYPE_OBJECT, RLM_PROPERTY_NULLABLE, "Person"),
    };
    const realm_property_info_t event_properties[] = {
        property(
            "id",
            RLM_PROPERTY_TYPE_INT,
            RLM_PROPERTY_PRIMARY_KEY | RLM_PROPERTY_INDEXED),
        property("title", RLM_PROPERTY_TYPE_STRING),
        property("priority", RLM_PROPERTY_TYPE_INT),
        property("owner", RLM_PROPERTY_TYPE_OBJECT, RLM_PROPERTY_NULLABLE, "Person"),
    };
    const realm_class_info_t classes[] = {
        {
            "Person",
            "id",
            std::size(person_properties),
            0,
            RLM_INVALID_CLASS_KEY,
            RLM_CLASS_NORMAL,
        },
        {
            "Event",
            "id",
            std::size(event_properties),
            0,
            RLM_INVALID_CLASS_KEY,
            RLM_CLASS_NORMAL,
        },
    };
    const realm_property_info_t* properties[] = {person_properties, event_properties};

    auto schema = take(
        realm_schema_new(classes, std::size(classes), properties),
        "create fixture schema");
    check(
        realm_schema_validate(schema.get(), RLM_SCHEMA_VALIDATION_BASIC),
        "validate fixture schema");

    auto config = take(realm_config_new(), "create fixture config");
    auto scheduler = make_scheduler();
    realm_config_set_path(config.get(), realm_path.c_str());
    realm_config_set_scheduler(config.get(), scheduler.get());
    realm_config_set_schema_mode(config.get(), RLM_SCHEMA_MODE_AUTOMATIC);
    realm_config_set_schema(config.get(), schema.get());
    realm_config_set_schema_version(config.get(), 1);
    check(
        realm_config_set_encryption_key(config.get(), key.data(), key.size()),
        "set fixture encryption key");

    auto realm = take(realm_open(config.get()), "open fixture Realm");
    realm_class_info_t person_class{};
    realm_class_info_t event_class{};
    bool found = false;
    check(
        realm_find_class(realm.get(), "Person", &found, &person_class) && found,
        "find Person class");
    check(
        realm_find_class(realm.get(), "Event", &found, &event_class) && found,
        "find Event class");

    auto find_property = [&](realm_class_key_t class_key, const char* name) {
        realm_property_info_t info{};
        bool property_found = false;
        check(
            realm_find_property(realm.get(), class_key, name, &property_found, &info)
                && property_found,
            std::string("find property ") + name);
        return info.key;
    };

    const auto person_name = find_property(person_class.key, "name");
    const auto person_age = find_property(person_class.key, "age");
    const auto person_friend = find_property(person_class.key, "friend");
    const auto event_title = find_property(event_class.key, "title");
    const auto event_priority = find_property(event_class.key, "priority");
    const auto event_owner = find_property(event_class.key, "owner");

    check(realm_begin_write(realm.get()), "begin fixture transaction");
    auto alice = take(
        realm_object_create_with_primary_key(realm.get(), person_class.key, integer(1)),
        "create Alice");
    auto bob = take(
        realm_object_create_with_primary_key(realm.get(), person_class.key, integer(2)),
        "create Bob");
    check(realm_set_value(alice.get(), person_name, string("Alice"), false), "set Alice name");
    check(realm_set_value(alice.get(), person_age, integer(34), false), "set Alice age");
    check(realm_set_value(bob.get(), person_name, string("Bob"), false), "set Bob name");
    check(realm_set_value(bob.get(), person_age, integer(29), false), "set Bob age");
    check(realm_set_value(alice.get(), person_friend, link(bob.get()), false), "link Alice");
    check(realm_set_value(bob.get(), person_friend, link(alice.get()), false), "link Bob");

    auto first_event = take(
        realm_object_create_with_primary_key(realm.get(), event_class.key, integer(10)),
        "create first event");
    auto second_event = take(
        realm_object_create_with_primary_key(realm.get(), event_class.key, integer(11)),
        "create second event");
    check(
        realm_set_value(first_event.get(), event_title, string("Review evidence"), false),
        "set first event title");
    check(
        realm_set_value(first_event.get(), event_priority, integer(3), false),
        "set first event priority");
    check(
        realm_set_value(first_event.get(), event_owner, link(alice.get()), false),
        "set first event owner");
    check(
        realm_set_value(second_event.get(), event_title, string("Write report"), false),
        "set second event title");
    check(
        realm_set_value(second_event.get(), event_priority, integer(1), false),
        "set second event priority");
    check(
        realm_set_value(second_event.get(), event_owner, link(bob.get()), false),
        "set second event owner");
    check(realm_commit(realm.get()), "commit fixture transaction");
    return 0;
}
catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
}
