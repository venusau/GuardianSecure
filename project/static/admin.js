function getUsers() {
    fetch("/users")
      .then((response) => response.json())
      .then((data) => {
        const users = data.users;
        console.log(data)
        const tableBody = document.getElementById("userTable");
        tableBody.innerHTML = "";
        users.forEach((user) => {
          const row = document.createElement("tr");
          row.className = "border-t border-slate-800/80 transition hover:bg-slate-800/30";
          row.innerHTML = `
                        <td class="px-5 py-3.5 text-slate-400">${user.id}</td>
                        <td class="px-5 py-3.5 font-medium text-white">${user.name}</td>
                        <td class="px-5 py-3.5 text-slate-400">${user.email}</td>
                        <td class="px-5 py-3.5">
                            <button onclick="updateUser(${user.id})" class="rounded-lg border border-emerald-500/50 px-3 py-1 text-xs font-semibold text-emerald-300 transition hover:bg-emerald-500/10">Update</button>
                            <button onclick="deleteUser(${user.id})" class="ml-1 rounded-lg border border-rose-500/50 px-3 py-1 text-xs font-semibold text-rose-300 transition hover:bg-rose-500/10">Delete</button>
                        </td>
                    `;
          tableBody.appendChild(row);
        });
      })
      .catch((error) => alert("Error:", error));
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
                if (response.status===401){
                    alert("You can not update this user");
                }
                else{
                    alert("Failed to update user");
                }
            }
        } catch (error) {
            alert("Error:", error);
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
            if (response.status===401){
                alert("You can not delete this user");
                getUsers();
            }
            else{
                alert("Failed to delete user");
            }
        }
    } catch (error) {
        alert("Error:", error);
    }
}

  // Call the function to fetch users when the page loads
  getUsers();