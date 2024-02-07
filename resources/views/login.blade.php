<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Passkey Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet"
          integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous">
    <link rel="stylesheet" href="https://unpkg.com/@corbado/web-js@latest/dist/bundle/index.css"/>
    @vite(['resources/css/app.css'])

</head>
<body>
<div class="container p-5" id="app">
    <div class="row">
        <div class="col-md-4 mx-auto">

            <div class="card" v-if="!register">
                <div class="card-header">
                    <p>Authenticate with passkey</p>
                </div>
                <div class="card-body">
                    <label>Username or Email</label>
                    <input v-model="userName" type="email" class="form-control">
                    <button @click="getOptions" class="btn btn-primary btn-block btn-lg mt-2 w-100">Authenticate
                    </button>
                </div>
            </div>

            <div class="card" v-else>
                <div class="card-header">
                    <p>Register for passkey</p>
                </div>
                <div class="card-body">

                    <label>Full name</label>
                    <input v-model="name" type="text" class="form-control">

                    <label>Username or Email</label>
                    <input v-model="userName" type="text" class="form-control">

                    <button @click="registerUser" class="btn btn-primary btn-block btn-lg mt-2 w-100">Register
                    </button>
                </div>
            </div>




        </div>
    </div>
</div>
@vite('resources/js/app.js')

</body>
</html>
