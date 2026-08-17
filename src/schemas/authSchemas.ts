import { z } from "zod";

export const emailSchema = z.email("Invalid email address");

export const passwordSchema = z
  .string()
  .min(8, "Password must be at least 8 characters long")
  .regex(/[a-z]/, "Password must contain a lowercase letter")
  .regex(/[A-Z]/, "Password must contain an uppercase letter")
  .regex(/[0-9]/, "Password must contain a number");

export const rememberSchema = z.boolean().optional();

export const nameFieldSchema = z
  .string()
  .trim()
  .min(1, "Name cannot be empty")
  .max(100, "Name is too long")
  .optional();

export const addressSchema = z
  .object({
    state: z.string().trim().max(100, "State is too long").optional(),
    city: z.string().trim().max(100, "City is too long").optional(),
    line: z.string().trim().max(300, "Address is too long").optional(),
  })
  .optional()
  .nullable()
  .transform((data) => {
    if (!data) return null;
    if (!data.state && !data.city && !data.line) return null;
    return data;
  });

export const registerSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  firstName: nameFieldSchema,
  lastName: nameFieldSchema,
  remember: rememberSchema,
});

export const credentialsSchema = z.object({
  email: z.string().min(1, "Email is required"),
  password: z.string().min(1, "Password is required"),
  remember: rememberSchema,
});

export const updateProfileSchema = z.object({
  firstName: nameFieldSchema,
  lastName: nameFieldSchema,
  phone: z.string().trim().max(30, "Phone number is too long").optional(),
  birthDate: z.string().date("Invalid birth date").optional(),
  image: z.string().trim().max(500, "Image URL is too long").optional(),
  address: z.preprocess(
    (val) => (typeof val === "string" ? JSON.parse(val) : val),
    addressSchema,
  ),
});

const currentPasswordField = z.string().min(1, "Current password is required").optional();

export const changePasswordSchema = z.object({
  currentPassword: currentPasswordField,
  newPassword: passwordSchema,
});

export const currentPasswordSchema = z.object({
  currentPassword: currentPasswordField,
});
