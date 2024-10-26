const handleCastErrorDB = (err) => ({
  status: "fail",
  message: `Invalid ${err.path}: ${err.value}`,
  statusCode: 400,
});

const handleDuplicateFieldsDB = (err) => ({
  status: "fail",
  message: `Duplicate field value: ${Object.values(err.keyValue).join(". ")}`,
  statusCode: 400,
});

const handleValidationErrorDB = (err) => ({
  status: "fail",
  message: Object.values(err.errors)
    .map((el) => el.message)
    .join(". "),
  statusCode: 400,
});

const errorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || "error";

  if (process.env.NODE_ENV === "development") {
    res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
      stack: err.stack,
      error: err,
    });
  } else {
    let error = { ...err };
    error.message = err.message;

    if (err.name === "CastError") error = handleCastErrorDB(err);
    if (err.code === 11000) error = handleDuplicateFieldsDB(err);
    if (err.name === "ValidationError") error = handleValidationErrorDB(err);

    res.status(error.statusCode || err.statusCode).json({
      status: error.status || err.status,
      message: error.message || "Something went wrong!",
    });
  }
};

module.exports = errorHandler;
