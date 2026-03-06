async function login(){

    const email = document.getElementById("email").value
    const password = document.getElementById("password").value

    const response = await fetch("/login",{
        method:"POST",
        headers:{
            "Content-Type":"application/json"
        },
        body:JSON.stringify({
            email:email,
            password:password
        })
    })

    const data = await response.json()

    if(data.token){

        localStorage.setItem("token",data.token)

        document.getElementById("message").innerText="Login successful"

        window.location="/dashboard"

    }else{

        document.getElementById("message").innerText=data.error

    }
}