// @generated automatically by Diesel CLI.

diesel::table! {
    outbox_events (id) {
        id -> Uuid,
        event_type -> Varchar,
        aggregate_type -> Varchar,
        aggregate_id -> Uuid,
        payload -> Jsonb,
        published -> Bool,
        published_at -> Nullable<Timestamp>,
        created_at -> Timestamp,
    }
}

diesel::table! {
    password_reset_tokens (id) {
        id -> Uuid,
        user_id -> Uuid,
        token_hash -> Varchar,
        expires_at -> Timestamp,
        used_at -> Nullable<Timestamp>,
        created_at -> Timestamp,
    }
}

diesel::table! {
    permissions (id) {
        id -> Uuid,
        project_id -> Uuid,
        name -> Varchar,
        description -> Nullable<Text>,
        resource -> Varchar,
        action -> Varchar,
        created_at -> Timestamp,
    }
}

diesel::table! {
    project_members (id) {
        id -> Uuid,
        project_id -> Uuid,
        user_id -> Uuid,
        role_id -> Uuid,
        joined_at -> Timestamp,
    }
}

diesel::table! {
    projects (id) {
        id -> Uuid,
        name -> Varchar,
        slug -> Varchar,
        description -> Nullable<Text>,
        owner_id -> Uuid,
        is_active -> Bool,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    refresh_tokens (id) {
        id -> Uuid,
        user_id -> Uuid,
        token_hash -> Varchar,
        expires_at -> Timestamp,
        created_at -> Timestamp,
    }
}

diesel::table! {
    role_permissions (role_id, permission_id) {
        role_id -> Uuid,
        permission_id -> Uuid,
        created_at -> Timestamp,
    }
}

diesel::table! {
    roles (id) {
        id -> Uuid,
        project_id -> Uuid,
        name -> Varchar,
        description -> Nullable<Text>,
        created_at -> Timestamp,
    }
}

diesel::table! {
    user_permissions (id) {
        id -> Uuid,
        project_id -> Uuid,
        user_id -> Uuid,
        permission_id -> Uuid,
        granted -> Bool,
        created_at -> Timestamp,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        email -> Varchar,
        password_hash -> Varchar,
        full_name -> Nullable<Varchar>,
        is_active -> Bool,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::joinable!(password_reset_tokens -> users (user_id));
diesel::joinable!(permissions -> projects (project_id));
diesel::joinable!(project_members -> projects (project_id));
diesel::joinable!(project_members -> roles (role_id));
diesel::joinable!(project_members -> users (user_id));
diesel::joinable!(projects -> users (owner_id));
diesel::joinable!(refresh_tokens -> users (user_id));
diesel::joinable!(role_permissions -> permissions (permission_id));
diesel::joinable!(role_permissions -> roles (role_id));
diesel::joinable!(roles -> projects (project_id));
diesel::joinable!(user_permissions -> permissions (permission_id));
diesel::joinable!(user_permissions -> projects (project_id));
diesel::joinable!(user_permissions -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    outbox_events,
    password_reset_tokens,
    permissions,
    project_members,
    projects,
    refresh_tokens,
    role_permissions,
    roles,
    user_permissions,
    users,
);
