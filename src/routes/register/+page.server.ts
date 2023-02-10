import { fail, redirect } from '@sveltejs/kit';
import type { Action, Actions, PageServerLoad } from './$types';
import bcrypt from 'bcrypt';
import { prisma } from '$lib/prisma';
import { z } from 'zod';
import { ZodError } from 'zod';

enum Roles {
	ADMIN = 'ADMIN',
	USER = 'USER'
}

export const load: PageServerLoad = async () => {};

const registerSchema = z.object({
	username: z
		.string()
		.min(1, 'You should provide an Username')
		.max(50, 'Your username should be less than 50 characters long'),
	password: z
		.string()
		.min(1, 'You Should provide a password')
		.max(70, 'Your password should be less than 70 characters long')
});

type RegisterDTO = z.infer<typeof registerSchema>;

const register: Action = async ({ request }) => {
	const data = await request.formData();
	const username = data.get('username') as string;
	const password = data.get('password') as string;

	let parsed: RegisterDTO;

	try {
		parsed = registerSchema.parse({ username, password });
	} catch (e) {
		if (e instanceof ZodError) {
			return fail(400, { message: e.issues[0].message });
		} else {
			return fail(500, { message: 'Internal Server Error' });
		}
	}

	const user = await prisma.user.findUnique({
		where: { username }
	});

	if (user) {
		return fail(409, { userAlreadyExists: true });
	}

	const passwordHash = await bcrypt.hash(parsed.password, 10);

	await prisma.user.create({
		data: {
			username: parsed.username,
			passwordHash,
			userAuthToken: crypto.randomUUID(),
			role: { connect: { name: Roles.USER } }
		}
	});

	throw redirect(303, '/login');
};

export const actions: Actions = { register };
