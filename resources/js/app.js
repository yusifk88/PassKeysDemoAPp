import './bootstrap';
import {
    startAuthentication,
    startRegistration,
    browserSupportsWebAuthn,
} from '@simplewebauthn/browser';

import {createApp} from 'vue/dist/vue.esm-bundler';

createApp({
    data() {
        return {
            counter: 1,
            email: "",
            register: false,
            name: ""
        }
    },
    methods: {

        getOptions() {

            axios.post("/passkey-auth/options", {
                email: this.email
            })
                .then(res => startRegistration(res.data))
                .then(attRes => {
                    console.log(attRes);
                })

                .catch(error => {

                    console.log(error);


                    if (error.response.status === 401) {

                        this.register = true;
                    }
                })

        }
        ,
        registerUser() {

            /**
             *
             * @type {{name: string, userName: string}}
             */

            const data = {
                name: this.name,
                email: this.email

            };


            axios.post("/passkey-auth/register/options", data)
                .then(res => startRegistration(res.data))
                .then(attRes => {

                    axios.post("/passkey-auth/register/verify", attRes)
                        .then(res => {
                            console.log(res.data);
                        })

                })


        }

    }
}).mount('#app');
