ALTER TABLE public.doctor_prescriptions
  ADD COLUMN IF NOT EXISTS current_avg_rx numeric(10,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS target_avg_rx numeric(10,2) NOT NULL DEFAULT 0;

ALTER TABLE public.doctor_prescriptions
  ADD CONSTRAINT doctor_prescriptions_current_avg_rx_nonnegative
    CHECK (current_avg_rx >= 0) NOT VALID,
  ADD CONSTRAINT doctor_prescriptions_target_avg_rx_nonnegative
    CHECK (target_avg_rx >= 0) NOT VALID;

ALTER TABLE public.doctor_prescriptions
  VALIDATE CONSTRAINT doctor_prescriptions_current_avg_rx_nonnegative;
ALTER TABLE public.doctor_prescriptions
  VALIDATE CONSTRAINT doctor_prescriptions_target_avg_rx_nonnegative;
