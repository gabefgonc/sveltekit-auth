import { fail, redirect } from '@sveltejs/kit';
import bcrypt from 'bcrypt';
import type { Action, Actions, PageServerLoad } from './$types';

import { prisma } from '$lib/prisma';
import { z } from 'zod';
import { ZodError } from 'zod';

export const load: PageServerLoad = async () => {
	// todo
};

const loginSchema = z.object({
	username: z.string().min(1, 'You should provide an Username'),
	password: z.string().min(1, 'You Should provide a password')
});

type LoginDTO = z.infer<typeof loginSchema>;

const login: Action = async ({ cookies, request }) => {
	const data = await request.formData();
	const username = data.get('username');
	const password = data.get('password');

	let parsed: LoginDTO;

	try {
		parsed = loginSchema.parse({ username, password });
	} catch (e) {
		if (e instanceof ZodError) {
			return fail(400, { message: e.issues[0].message });
		} else {
			return fail(500, { message: 'Internal Server Error' });
		}
	}

	const user = await prisma.user.findUnique({ where: { username: parsed.username } });

	if (!user) {
		return fail(400, { credentials: true });
	}

	const userPassword = await bcrypt.compare(parsed.password, user.passwordHash);

	if (!userPassword) {
		return fail(400, { credentials: true });
	}

	const authenticatedUser = await prisma.user.update({
		where: { username: user.username },
		data: { userAuthToken: crypto.randomUUID() }
	});

	cookies.set('session', authenticatedUser.userAuthToken, {
		path: '/',
		httpOnly: true,
		sameSite: 'strict',
		secure: process.env.NODE_ENV === 'production',
		maxAge: 60 * 60 * 24 * 30
	});

	throw redirect(302, '/');
};

export const actions: Actions = { login };
