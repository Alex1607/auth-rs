import { writable } from 'svelte/store';

export const apiUrl = writable<string>('http://localhost/api');