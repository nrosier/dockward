import * as RadixSwitch from "@radix-ui/react-switch";

interface SwitchProps {
  id: string;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  disabled?: boolean;
}

export function Switch({ id, checked, onCheckedChange, disabled }: SwitchProps) {
  return (
    <RadixSwitch.Root
      id={id}
      checked={checked}
      onCheckedChange={onCheckedChange}
      disabled={disabled}
      className="relative h-6 w-11 cursor-pointer rounded-full border border-border bg-surface-2 data-[state=checked]:border-accent data-[state=checked]:bg-accent disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
    >
      <RadixSwitch.Thumb className="block size-[18px] translate-x-0.5 rounded-full bg-text transition-transform data-[state=checked]:translate-x-[22px] data-[state=checked]:bg-on-accent" />
    </RadixSwitch.Root>
  );
}
