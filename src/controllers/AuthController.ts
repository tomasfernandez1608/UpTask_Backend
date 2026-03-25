import type { Request, Response } from 'express';
import User from '../models/User';
import Token from '../models/Token';
import { checkPassword, hashPassword } from '../utils/auth';
import { generateToken } from '../utils/token';
import { AuthEmail } from '../emails/AuthEmail';
import { generateJWT } from '../utils/jwt';

export class AuthController {

    static createAccount = async (req: Request, res: Response) => {
        try {
            const { password, email } = req.body;

            const userExists = await User.findOne({ email });
            if (userExists) {
                return res.status(409).json({ error: 'El Usuario ya esta registrado' });
            }

            const user = new User(req.body);
            user.password = await hashPassword(password);

            const token = new Token();
            token.token = generateToken();
            token.user = user.id;

            AuthEmail.sendConfirmationEmail({
                email: user.email,
                name: user.name,
                token: token.token
            });

            await Promise.allSettled([user.save(), token.save()]);
            res.send('Cuenta creada, revisa tu email para confirmarla');

        } catch (error) {
            res.status(500).json({ error: 'Hubo un error' });
        }
    };

    static confirmAccount = async (req: Request, res: Response) => {
        try {
            const { token } = req.body;

            const tokenExists = await Token.findOne({ token });
            if (!tokenExists) {
                return res.status(404).json({ error: 'Token no válido' });
            }

            const user = await User.findById(tokenExists.user);
            if (!user) {
                return res.status(404).json({ error: 'Usuario no encontrado' });
            }

            user.confirmed = true;

            await Promise.allSettled([user.save(), tokenExists.deleteOne()]);
            res.send('Cuenta confirmada correctamente');

        } catch (error) {
            res.status(500).json({ error: 'Hubo un error' });
        }
    };

    static login = async (req: Request, res: Response) => {
        try {
            const { email, password } = req.body;

            const user = await User.findOne({ email });
            if (!user) {
                return res.status(404).json({ error: 'Usuario no encontrado' });
            }

            if (!user.confirmed) {
                const token = new Token();
                token.user = user.id;
                token.token = generateToken();
                await token.save();

                AuthEmail.sendConfirmationEmail({
                    email: user.email,
                    name: user.name,
                    token: token.token
                });

                return res.status(401).json({
                    error: 'La cuenta no ha sido confirmada, hemos enviado un e-mail de confirmación'
                });
            }

            const isPasswordCorrect = await checkPassword(password, user.password);
            if (!isPasswordCorrect) {
                return res.status(401).json({ error: 'Password Incorrecto' });
            }

            // ✅ FIX IMPORTANTE
            const token = generateJWT({ id: user._id.toString() });

            res.send(token);

        } catch (error) {
            res.status(500).json({ error: 'Hubo un error' });
        }
    };

    static requestConfirmationCode = async (req: Request, res: Response) => {
        try {
            const { email } = req.body;

            const user = await User.findOne({ email });
            if (!user) {
                return res.status(404).json({ error: 'El Usuario no esta registrado' });
            }

            if (user.confirmed) {
                return res.status(403).json({ error: 'El Usuario ya esta confirmado' });
            }

            const token = new Token();
            token.token = generateToken();
            token.user = user.id;

            AuthEmail.sendConfirmationEmail({
                email: user.email,
                name: user.name,
                token: token.token
            });

            await Promise.allSettled([user.save(), token.save()]);
            res.send('Se envió un nuevo token a tu e-mail');

        } catch (error) {
            res.status(500).json({ error: 'Hubo un error' });
        }
    };

    static forgotPassword = async (req: Request, res: Response) => {
        try {
            const { email } = req.body;

            const user = await User.findOne({ email });
            if (!user) {
                return res.status(404).json({ error: 'El Usuario no esta registrado' });
            }

            const token = new Token();
            token.token = generateToken();
            token.user = user.id;
            await token.save();

            AuthEmail.sendPasswordResetToken({
                email: user.email,
                name: user.name,
                token: token.token
            });

            res.send('Revisa tu email para instrucciones');

        } catch (error) {
            res.status(500).json({ error: 'Hubo un error' });
        }
    };

    static validateToken = async (req: Request, res: Response) => {
        try {
            const { token } = req.body;

            const tokenExists = await Token.findOne({ token });
            if (!tokenExists) {
                return res.status(404).json({ error: 'Token no válido' });
            }

            res.send('Token válido, Define tu nuevo password');

        } catch (error) {
            res.status(500).json({ error: 'Hubo un error' });
        }
    };

    static updatePasswordWithToken = async (req: Request, res: Response) => {
        try {
            const { token } = req.params;
            const { password } = req.body;

            const tokenExists = await Token.findOne({ token });
            if (!tokenExists) {
                return res.status(404).json({ error: 'Token no válido' });
            }

            const user = await User.findById(tokenExists.user);
            if (!user) {
                return res.status(404).json({ error: 'Usuario no encontrado' });
            }

            user.password = await hashPassword(password);

            await Promise.allSettled([user.save(), tokenExists.deleteOne()]);
            res.send('El password se modificó correctamente');

        } catch (error) {
            res.status(500).json({ error: 'Hubo un error' });
        }
    };

    static user = async (req: Request, res: Response) => {
        return res.json(req.user);
    };

    static updateProfile = async (req: Request, res: Response) => {
        const { name, email } = req.body;

        const userExists = await User.findOne({ email });
        if (userExists && userExists.id.toString() !== req.user.id.toString()) {
            return res.status(409).json({ error: 'Ese email ya esta registrado' });
        }

        req.user.name = name;
        req.user.email = email;

        try {
            await req.user.save();
            res.send('Perfil actualizado correctamente');
        } catch (error) {
            res.status(500).send('Hubo un error');
        }
    };

    static updateCurrentUserPassword = async (req: Request, res: Response) => {
        const { current_password, password } = req.body;

        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        const isPasswordCorrect = await checkPassword(current_password, user.password);
        if (!isPasswordCorrect) {
            return res.status(401).json({ error: 'El Password actual es incorrecto' });
        }

        try {
            user.password = await hashPassword(password);
            await user.save();
            res.send('El Password se modificó correctamente');
        } catch (error) {
            res.status(500).send('Hubo un error');
        }
    };

    static checkPassword = async (req: Request, res: Response) => {
        const { password } = req.body;

        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        const isPasswordCorrect = await checkPassword(password, user.password);
        if (!isPasswordCorrect) {
            return res.status(401).json({ error: 'El Password es incorrecto' });
        }

        res.send('Password Correcto');
    };
}