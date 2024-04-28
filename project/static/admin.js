function getUsers() {
    fetch("/users")
      .then((response) => response.json())
      .then((data) => {
        const users = data.users;
        const tableBody = document.getElementById("userTable");
        tableBody.innerHTML = "";
        users.forEach((user) => {
          const row = document.createElement("tr");
          row.innerHTML = `
                        <td>${user.id}</td>
                        <td>${user.name}</td>
                        <td>${user.email}</td>
                        <td>
                            <button onclick="updateUser(${user.id})">Update</button>
                            <button onclick="deleteUser(${user.id})">Delete</button>
                        </td>
                    `;
          tableBody.appendChild(row);
        });
      })
      .catch((error) => console.error("Error:", error));
  }
  
  function openModal() {
    document.getElementById('overlay').style.display = 'block';
    document.getElementById('modal').style.display = 'block';
}

function closeModal() {
    document.getElementById('overlay').style.display = 'none';
    document.getElementById('modal').style.display = 'none';
}

function updateUser(userId) {
    // Open modal
    openModal();

    // Function to handle form submission when updating user
    const updateUserForm = document.getElementById("updateUserForm");
    updateUserForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        
        const name = document.getElementById("updateUserName").value;
        const email = document.getElementById("updateUserEmail").value;

        try {
            const response = await fetch(`/update_user/${userId}`, {
                method: "PATCH",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ name, email })
            });

            if (response.ok) {
                // Refresh the user list after updating
                closeModal();
                getUsers();
            } else {
                console.error("Failed to update user");
            }
        } catch (error) {
            console.error("Error:", error);
        }
    });
}

async function deleteUser(userId) {
    // Implement delete functionality using DELETE method
    try {
        const response = await fetch(`/delete_user/${userId}`, {
            method: "DELETE"
        });

        if (response.ok) {
            // Refresh the user list after deleting
            getUsers();
        } else {
            console.error("Failed to delete user");
        }
    } catch (error) {
        console.error("Error:", error);
    }
}

  // Call the function to fetch users when the page loads
  getUsers();