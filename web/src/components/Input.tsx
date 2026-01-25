export default function Input({
  label,
  type = "text",
  name,
  value,
  onChange,
  placeholder,
  wrapperClassName = "input",
  inputClassName = "",
  labelClassName = "",
  ...rest
}) {
  return (
    <div className={wrapperClassName}>
      <label className={labelClassName}>{label}</label>
      <input
        type={type}
        name={name}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        className={inputClassName}
        {...rest}
      />
    </div>
  );
}
