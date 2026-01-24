export default function InputField({ label, type = "text", name, value, onChange, placeholder, ...rest }) {
  return (
    <div className="input">
      <label>{label}</label>
      <input
        type={type}
        name={name}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        {...rest}
      />
    </div>
  );
}
