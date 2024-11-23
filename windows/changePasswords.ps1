# Define the new password
$newPassword = "NewPassword123!"

# Get all local user accounts
$users = Get-LocalUser

# Loop through each user and set the new password
foreach ($user in $users) {
    # Exclude system and built-in accounts (e.g., Administrator, Guest)
    # if ($user.Name -ne "Administrator" -and $user.Name -ne "Guest") {
        # Set the new password for the user
        try {
            Set-LocalUser -Name $user.Name -Password (ConvertTo-SecureString -AsPlainText $newPassword -Force)
            Write-Host "Password for user $($user.Name) changed successfully."
        }
        catch {
            Write-Host "Failed to change password for user $($user.Name): $_"
        }
    }
}

