//! Politica RBAC proposta; o servidor nao a aplica ate a fase 6.3.
//! Nao confundir usuario cadastrado em api_users com conta autenticada.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Role {
    Viewer,
    Editor,
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Operation {
    ReadUsers,
    CreateUsers,
    ModifyUsers,
    DeleteUsers,
    ManageCredentials,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Decision {
    Allow,
    Unauthenticated, // Futuro HTTP 401
    Forbidden,       // Futuro HTTP 403
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Identity {
    pub(super) account_id: u64,
    pub(super) role: Role,
    pub(super) active: bool,
}

pub(super) fn authorize(identity: Option<&Identity>, operation: Operation) -> Decision {
    let Some(identity) = identity else {
        return Decision::Unauthenticated;
    };
    if !identity.active || identity.account_id == 0 {
        return Decision::Forbidden;
    }
    let permitted = match identity.role {
        Role::Viewer => matches!(operation, Operation::ReadUsers),
        Role::Editor => matches!(
            operation,
            Operation::ReadUsers | Operation::CreateUsers | Operation::ModifyUsers
        ),
        Role::Admin => true,
    };
    if permitted {
        Decision::Allow
    } else {
        Decision::Forbidden
    }
}
