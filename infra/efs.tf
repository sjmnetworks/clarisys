# --- EFS (Persistent State) ------------------------------------------------

resource "aws_efs_file_system" "state" {
  creation_token = "${var.project_name}-state"
  encrypted      = true

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }

  tags = { Name = "${var.project_name}-efs" }
}

resource "aws_efs_mount_target" "state" {
  count           = 2
  file_system_id  = aws_efs_file_system.state.id
  subnet_id       = aws_subnet.private[count.index].id
  security_groups = [aws_security_group.efs.id]
}

# Access point for the app (enforces uid/gid 1001 matching Dockerfile)
resource "aws_efs_access_point" "app" {
  file_system_id = aws_efs_file_system.state.id

  posix_user {
    uid = 1001
    gid = 1001
  }

  root_directory {
    path = "/firewall-api"
    creation_info {
      owner_uid   = 1001
      owner_gid   = 1001
      permissions = "0755"
    }
  }

  tags = { Name = "${var.project_name}-ap" }
}
