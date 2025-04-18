<script lang="ts">
	import RoleList from '../../lib/components/dashboard/RoleList.svelte';
	import TextField from "$lib/components/global/TextField.svelte";
	import { onMount } from 'svelte';
	import type AuthRsApi from '$lib/api';
	import User from '$lib/models/User';
	import type Role from '$lib/models/Role';
	import DateUtils from '$lib/dateUtils';
	import TextInput from '$lib/components/global/TextInput.svelte';
	import Popup from '$lib/components/global/Popup.svelte';
	import UserUpdates from '$lib/models/UserUpdates';

    export let api: AuthRsApi;
    export let user: User;
    export let roles: Role[];

    let editUserPopup: boolean = false;
    let editUserEmail: string = '';
    let editUserFirstName: string = '';
    let editUserLastName: string = '';
    let editUserPassword: string = '';
    let editUserPasswordConfirm: string = '';

    $: editUserDataIsValid = () => {
        const emailValid = editUserEmail.length >= 5 && editUserEmail.includes('@') && editUserEmail.includes('.');
        const nameValid = editUserFirstName.length > 0;
        const passwordValid = (editUserPassword.length < 1 && editUserPasswordConfirm.length < 1) || (editUserPassword.length > 7 && editUserPassword === editUserPasswordConfirm);

        return emailValid && nameValid && passwordValid;
    }

    function showEditUserPopup() {
        editUserPopup = true;
        editUserEmail = user.email;
        editUserFirstName = user.firstName;
        editUserLastName = user.lastName;
        editUserPassword = '';
        editUserPasswordConfirm = '';
    }
    
    onMount(async () => {
        if (roles.length < 1) {
            api.getAllRoles()
                .then(r => roles = r)
                .catch(e => console.error(e));
        }
    });
</script>

{#if editUserPopup}
    <Popup title="Edit User" onClose={() => editUserPopup = false}>
        <div class="flex flex-col items-center justify-center min-w-[350px]">
            <TextInput type="email" label="Email" bind:value={editUserEmail} autocomplete="email" autofocus />
            <TextInput label="First Name" bind:value={editUserFirstName} autocomplete="name" />
            <TextInput label="Last Name" bind:value={editUserLastName} autocomplete="family-name" />
            <TextInput type="password" label="Password" bind:value={editUserPassword} autocomplete="new-password" />
            <TextInput type="password" label="Confirm Password" bind:value={editUserPasswordConfirm} autocomplete="new-password" />
            <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
            <!-- svelte-ignore a11y_click_events_have_key_events -->
            <p
                class="text-green-600 rounded-md {editUserDataIsValid() ? 'cursor-pointer' : 'cursor-default opacity-50'} text-[18px]"
                style="margin-top: 20px; margin-bottom: 10px;"
                on:click={editUserDataIsValid() ? () => {
                    editUserPopup = false;
                    api.updateUser(user!, new UserUpdates({ email: editUserEmail, password: editUserPassword.length < 1 ? null : editUserPassword, firstName: editUserFirstName, lastName: editUserLastName, roles: null, disabled: null }))
                        .then(editedUser => {
                            user = editedUser;
                        })
                        .catch(e => console.error(e));
                } : null}
            >Save</p>
        </div>
    </Popup>
{/if}

<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<div class="absolute flex flex-col min-h-[70px] items-center justify-center self-end" style="margin-right: 50px;">
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <p
        class="border-blue-500 text-blue-500 hover:bg-blue-500 hover:text-white transition-all border-[1.5px] cursor-pointer rounded-md"
        style="padding: 10px;"
        on:click={showEditUserPopup}
    >Edit Profile</p>
</div>
<div class="flex flex-col items-start justify-start h-[100%] w-full gap-[10px]">
    <TextField label="Full Name" value={`${user.firstName} ${user.lastName}`} onClick={showEditUserPopup} readonly={User.isSystemAdmin(user)} />
    <TextField label="Email" value={user.email} onClick={showEditUserPopup} readonly={User.isSystemAdmin(user)} />
    <RoleList label="Roles" roles={roles.filter(r => user.roles.includes(r._id))} onAdd={() => {}} onRemove={() => {}} readOnly isSystemAdmin={User.isSystemAdmin(user)} />
    <TextField label="Creation Date" value={DateUtils.getFullDateString(User.getCreatedAt(user))} readonly />
</div>