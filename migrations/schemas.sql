-- Create admins table if not exists
DO $$
BEGIN
    CREATE TABLE IF NOT EXISTS public.admins (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );
END $$;

-- Create users table if not exists
DO $$
BEGIN
    CREATE TABLE IF NOT EXISTS public.users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        admin_id UUID NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        access TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (admin_id) REFERENCES public.admins(id)
    );
END $$;

-- Create jobs table if not exists
DO $$
BEGIN
    CREATE TABLE IF NOT EXISTS public.jobs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        job_name TEXT NOT NULL,
        company_name TEXT NOT NULL,
        admin_id UUID NOT NULL,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (admin_id) REFERENCES public.admins(id)
    );
END $$;

