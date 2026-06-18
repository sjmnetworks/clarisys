package policy.nfr_compliance

import data.policy.nfr_requirements

# ──────────────────────────────────────────────────────────────────────────────
# TEST: FIREWALL ENCRYPTION VIOLATIONS
# ──────────────────────────────────────────────────────────────────────────────

test_firewall_payment_rule_requires_encryption if {
    input_data := {
        "firewall_rules": [
            {
                "name": "Payment Processing Rule",
                "action": "accept",
                "source": {"addresses": ["STORE_MAIN_DATA"], "interfaces": ["VLAN101"]},
                "destination": {"addresses": ["PAYMENT_GATEWAY"], "interfaces": ["VLAN200"]},
                "services": ["HTTPS"],
                "log": "all",
                "encryption_required": false,
                "tls_version_minimum": null,
                "comments": "Allows payment transactions"
            }
        ],
        "data_flows": [],
        "cloud_resources": [],
        "identity_operations": []
    }
    
    result := nfr_decision with input as input_data
    result.violations_count > 0
    some v in result.violations
    v.control == "Enc-Transit"
    v.severity == "CRITICAL"
}

test_firewall_payment_rule_with_tls_compliant if {
    input_data := {
        "firewall_rules": [
            {
                "name": "Payment Processing Rule",
                "action": "accept",
                "source": {"addresses": ["STORE_MAIN_DATA"], "interfaces": ["VLAN101"]},
                "destination": {"addresses": ["PAYMENT_GATEWAY"], "interfaces": ["VLAN200"]},
                "services": ["HTTPS"],
                "log": "all",
                "encryption_required": true,
                "tls_version_minimum": "1.2",
                "comments": "Allows payment transactions with TLS 1.2+"
            }
        ],
        "data_flows": [],
        "cloud_resources": [],
        "identity_operations": []
    }
    
    result := nfr_decision with input as input_data
    count({v | v := result.violations[_]; v.control == "Enc-Transit"}) == 0
}

test_firewall_all_services_violation if {
    input_data := {
        "firewall_rules": [
            {
                "name": "Overly Permissive Rule",
                "action": "accept",
                "source": {"addresses": ["GUEST_VLAN"], "interfaces": []},
                "destination": {"addresses": ["INTERNAL_SERVERS"], "interfaces": []},
                "services": ["ALL"],
                "log": "all",
                "encryption_required": false,
                "tls_version_minimum": null,
                "comments": "Allows all traffic"
            }
        ],
        "data_flows": [],
        "cloud_resources": [],
        "identity_operations": []
    }
    
    result := nfr_decision with input as input_data
    some v in result.violations
    v.control == "CIS_4.8"
    v.severity == "HIGH"
}

test_firewall_missing_logging_violation if {
    input_data := {
        "firewall_rules": [
            {
                "name": "Critical Server Access",
                "action": "accept",
                "source": {"addresses": ["MGMT_VLAN"], "interfaces": ["VLAN101"]},
                "destination": {"addresses": ["CRITICAL_SERVERS"], "interfaces": []},
                "services": ["SSH", "RDP"],
                "log": "no_log",
                "encryption_required": false,
                "tls_version_minimum": null,
                "comments": "Admin access (no logging!)"
            }
        ],
        "data_flows": [],
        "cloud_resources": [],
        "identity_operations": []
    }
    
    result := nfr_decision with input as input_data
    some v in result.violations
    v.control == "IAM-8"
    v.severity == "HIGH"
}

test_firewall_segmentation_violation if {
    input_data := {
        "firewall_rules": [
            {
                "name": "Default Rule - Missing Segmentation",
                "action": "accept",
                "source": {"addresses": [], "interfaces": []},
                "destination": {"addresses": ["INTERNAL_SERVERS"], "interfaces": []},
                "services": ["HTTP", "HTTPS"],
                "log": "all",
                "encryption_required": false,
                "tls_version_minimum": null,
                "comments": "Accept from anywhere"
            }
        ],
        "data_flows": [],
        "cloud_resources": [],
        "identity_operations": []
    }
    
    result := nfr_decision with input as input_data
    some v in result.violations
    v.control == "Cloud-08"
    v.severity == "HIGH"
}

# ──────────────────────────────────────────────────────────────────────────────
# TEST: DATA SECURITY VIOLATIONS
# ──────────────────────────────────────────────────────────────────────────────

test_data_missing_classification if {
    input_data := {
        "firewall_rules": [],
        "data_flows": [
            {
                "source_system": "POS_Terminal_Store_Main",
                "destination_system": "Payment_Processor",
                "data_classification": null,
                "encryption_in_transit": "TLS_1.2",
                "encryption_at_rest": "AES-256",
                "approved_external_sharing": false
            }
        ],
        "cloud_resources": [],
        "identity_operations": []
    }
    
    result := nfr_decision with input as input_data
    some v in result.violations
    v.control == "Data-01"
}

test_data_confidential_missing_encryption if {
    input_data := {
        "firewall_rules": [],
        "data_flows": [
            {
                "source_system": "Customer_Database",
                "destination_system": "Analytics_Platform",
                "data_classification": "Confidential",
                "encryption_in_transit": "HTTP",
                "encryption_at_rest": "AES-256",
                "approved_external_sharing": false
            }
        ],
        "cloud_resources": [],
        "identity_operations": []
    }
    
    result := nfr_decision with input as input_data
    some v in result.violations
    v.control == "Enc-Transit"
    v.severity == "CRITICAL"
}

test_data_external_sharing_without_contract if {
    input_data := {
        "firewall_rules": [],
        "data_flows": [
            {
                "source_system": "Stores_Database",
                "destination_system": "Third_Party_Analytics",
                "data_classification": "Internal",
                "encryption_in_transit": "TLS_1.2",
                "encryption_at_rest": "AES-256",
                "approved_external_sharing": true,
                "contract_reference": null
            }
        ],
        "cloud_resources": [],
        "identity_operations": []
    }
    
    result := nfr_decision with input as input_data
    some v in result.violations
    v.control == "Data-10"
}

test_data_test_environment_using_production_data if {
    input_data := {
        "firewall_rules": [],
        "data_flows": [
            {
                "source_system": "Production_Database",
                "destination_system": "Dev_Test_Environment",
                "environment": "dev",
                "data_classification": "Confidential",
                "uses_production_data": true,
                "data_anonymized": false,
                "data_masked": false,
                "encryption_in_transit": "TLS_1.2",
                "encryption_at_rest": "AES-256",
                "approved_external_sharing": false
            }
        ],
        "cloud_resources": [],
        "identity_operations": []
    }
    
    result := nfr_decision with input as input_data
    some v in result.violations
    v.control == "Data-11"
}

# ──────────────────────────────────────────────────────────────────────────────
# TEST: CLOUD SECURITY VIOLATIONS
# ──────────────────────────────────────────────────────────────────────────────

test_cloud_paas_without_private_endpoint if {
    input_data := {
        "firewall_rules": [],
        "data_flows": [],
        "cloud_resources": [
            {
                "name": "StoreDatabase",
                "resource_type": "Azure_SQLDatabase",
                "location": "UK South",
                "environment": "production",
                "private_endpoint_enabled": false,
                "encryption_enabled": true,
                "logging_enabled": true,
                "managed_identity_enabled": true,
                "tags": {"cost-center": "stores"}
            }
        ],
        "identity_operations": []
    }
    
    result := nfr_decision with input as input_data
    some v in result.violations
    v.control == "Cloud-02"
    v.severity == "CRITICAL"
}

test_cloud_resource_missing_encryption if {
    input_data := {
        "firewall_rules": [],
        "data_flows": [],
        "cloud_resources": [
            {
                "name": "StoreStorageAccount",
                "resource_type": "Azure_StorageAccount",
                "location": "UK South",
                "environment": "production",
                "private_endpoint_enabled": true,
                "encryption_enabled": false,
                "logging_enabled": true,
                "managed_identity_enabled": true,
                "tags": {"cost-center": "stores"}
            }
        ],
        "identity_operations": []
    }
    
    result := nfr_decision with input as input_data
    some v in result.violations
    v.control == "Cloud-04"
    v.severity == "CRITICAL"
}

test_cloud_keyvault_missing_soft_delete if {
    input_data := {
        "firewall_rules": [],
        "data_flows": [],
        "cloud_resources": [
            {
                "name": "PrimaryKeyVault",
                "resource_type": "Azure_KeyVault",
                "location": "UK South",
                "environment": "production",
                "soft_delete_enabled": false,
                "purge_protection_enabled": true,
                "logging_enabled": true,
                "encryption_enabled": true
            }
        ],
        "identity_operations": []
    }
    
    result := nfr_decision with input as input_data
    some v in result.violations
    v.control == "Cloud-04"
}

test_cloud_resource_missing_logging if {
    input_data := {
        "firewall_rules": [],
        "data_flows": [],
        "cloud_resources": [
            {
                "name": "StoreAppService",
                "resource_type": "Azure_AppService",
                "location": "UK South",
                "environment": "production",
                "private_endpoint_enabled": true,
                "encryption_enabled": true,
                "logging_enabled": false,
                "managed_identity_enabled": true
            }
        ],
        "identity_operations": []
    }
    
    result := nfr_decision with input as input_data
    some v in result.violations
    v.control == "Cloud-01"
    v.severity == "HIGH"
}

test_cloud_workload_without_managed_identity if {
    input_data := {
        "firewall_rules": [],
        "data_flows": [],
        "cloud_resources": [
            {
                "name": "StoreMicroservice",
                "resource_type": "Azure_AppService",
                "location": "UK South",
                "environment": "production",
                "private_endpoint_enabled": true,
                "encryption_enabled": true,
                "logging_enabled": true,
                "managed_identity_enabled": false
            }
        ],
        "identity_operations": []
    }
    
    result := nfr_decision with input as input_data
    some v in result.violations
    v.control == "Cloud-03"
    v.severity == "HIGH"
}

test_cloud_nsg_missing_deny_by_default if {
    input_data := {
        "firewall_rules": [],
        "data_flows": [],
        "cloud_resources": [
            {
                "name": "ProductionNSG",
                "resource_type": "Azure_NetworkSecurityGroup",
                "location": "UK South",
                "environment": "production",
                "inbound_rules": [
                    {"priority": 100, "action": "Allow", "source_address_prefix": "*", "destination_port": "443"},
                    {"priority": 101, "action": "Allow", "source_address_prefix": "10.0.0.0/8", "destination_port": "3306"}
                ]
            }
        ],
        "identity_operations": []
    }
    
    result := nfr_decision with input as input_data
    some v in result.violations
    v.control == "Cloud-08"
}

# ──────────────────────────────────────────────────────────────────────────────
# TEST: IDENTITY & ACCESS MANAGEMENT VIOLATIONS
# ──────────────────────────────────────────────────────────────────────────────

test_iam_password_only_authentication if {
    input_data := {
        "firewall_rules": [],
        "data_flows": [],
        "cloud_resources": [],
        "identity_operations": [
            {
                "user_id": "admin@stores.com",
                "operation_type": "authentication",
                "action": "login",
                "authentication_method": "password_only",
                "timestamp": "2026-05-15T10:00:00Z",
                "logged": true
            }
        ]
    }
    
    result := nfr_decision with input as input_data
    some v in result.violations
    v.control == "IAM-1"
    v.severity == "CRITICAL"
}

test_iam_elevated_access_without_approval if {
    input_data := {
        "firewall_rules": [],
        "data_flows": [],
        "cloud_resources": [],
        "identity_operations": [
            {
                "user_id": "user@stores.com",
                "operation_type": "elevated_access",
                "action": "request_global_admin",
                "approval_status": "pending",
                "timestamp": "2026-05-15T10:00:00Z",
                "logged": true
            }
        ]
    }
    
    result := nfr_decision with input as input_data
    some v in result.violations
    v.control == "IAM-3"
    v.severity == "CRITICAL"
}

test_iam_elevated_access_without_expiry if {
    input_data := {
        "firewall_rules": [],
        "data_flows": [],
        "cloud_resources": [],
        "identity_operations": [
            {
                "user_id": "admin@stores.com",
                "operation_type": "elevated_access",
                "action": "grant_admin_role",
                "approval_status": "approved",
                "expiry_date": null,
                "timestamp": "2026-05-15T10:00:00Z",
                "logged": true
            }
        ]
    }
    
    result := nfr_decision with input as input_data
    some v in result.violations
    v.control == "IAM-3"
    v.severity == "HIGH"
}

test_iam_access_operation_not_logged if {
    input_data := {
        "firewall_rules": [],
        "data_flows": [],
        "cloud_resources": [],
        "identity_operations": [
            {
                "user_id": "user@stores.com",
                "operation_type": "role_assignment",
                "action": "assign_reader_role",
                "timestamp": "2026-05-15T10:00:00Z",
                "logged": false
            }
        ]
    }
    
    result := nfr_decision with input as input_data
    some v in result.violations
    v.control == "IAM-8"
}

# ──────────────────────────────────────────────────────────────────────────────
# TEST: FULLY COMPLIANT SCENARIO
# ──────────────────────────────────────────────────────────────────────────────

test_complete_compliance_passing if {
    input_data := {
        "firewall_rules": [
            {
                "name": "Secure Payment Processing",
                "action": "accept",
                "source": {"addresses": ["STORE_MAIN_POS"], "interfaces": ["VLAN101"]},
                "destination": {"addresses": ["PAYMENT_GATEWAY"], "interfaces": ["VLAN200"]},
                "services": ["HTTPS"],
                "log": "all",
                "encryption_required": true,
                "tls_version_minimum": "1.2",
                "comments": "PCI-compliant payment rule with TLS 1.2+, logged"
            },
            {
                "name": "Internal Database Access",
                "action": "accept",
                "source": {"addresses": ["APP_SERVERS"], "interfaces": ["VLAN102"]},
                "destination": {"addresses": ["INTERNAL_DB"], "interfaces": ["VLAN103"]},
                "services": ["MySQL"],
                "log": "all",
                "encryption_required": true,
                "tls_version_minimum": "1.2",
                "comments": "Database access with TLS, logged"
            }
        ],
        "data_flows": [
            {
                "source_system": "POS_System",
                "destination_system": "Payment_Processor",
                "data_classification": "Highly Confidential",
                "encryption_in_transit": "TLS_1.3",
                "encryption_at_rest": "AES-256",
                "approved_external_sharing": true,
                "contract_reference": "DPA-2026-005"
            },
            {
                "source_system": "Store_Database",
                "destination_system": "Internal_Analytics",
                "data_classification": "Internal",
                "encryption_in_transit": "TLS_1.2",
                "encryption_at_rest": "AES-256",
                "approved_external_sharing": false
            }
        ],
        "cloud_resources": [
            {
                "name": "StoreDatabase",
                "resource_type": "Azure_SQLDatabase",
                "location": "UK South",
                "environment": "production",
                "private_endpoint_enabled": true,
                "encryption_enabled": true,
                "logging_enabled": true,
                "managed_identity_enabled": true,
                "soft_delete_enabled": true,
                "purge_protection_enabled": true,
                "tags": {"cost-center": "stores"}
            },
            {
                "name": "PrimaryKeyVault",
                "resource_type": "Azure_KeyVault",
                "location": "UK South",
                "environment": "production",
                "soft_delete_enabled": true,
                "purge_protection_enabled": true,
                "logging_enabled": true,
                "encryption_enabled": true
            }
        ],
        "identity_operations": [
            {
                "user_id": "admin@stores.com",
                "operation_type": "authentication",
                "action": "login",
                "authentication_method": "mfa_enabled",
                "timestamp": "2026-05-15T10:00:00Z",
                "logged": true
            },
            {
                "user_id": "user@stores.com",
                "operation_type": "elevated_access",
                "action": "request_global_admin",
                "approval_status": "approved",
                "expiry_date": "2026-05-15T18:00:00Z",
                "timestamp": "2026-05-15T10:00:00Z",
                "justification": "Emergency production support",
                "approver": "manager@stores.com",
                "logged": true
            }
        ]
    }
    
    result := nfr_decision with input as input_data
    result.violations_count == 0
    result.compliant == true
}
