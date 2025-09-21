import { ApiResponse } from "../utils/apiRsponse.js";
import asyncHandler from "../utils/asyncHandler.js";

// const helthCheck = (req, res) => {
//   try {
//     res
//       .status(200)
//       .json(new ApiResponse(200, { message: "server is running" }));
//   } catch (error) {
//     console.log();
//   }
// };

// ANOTHER WAY OF WRITTING
const helthCheck = asyncHandler(async (req, res) => {
  res.status(200).json(new ApiResponse(200, { message: "server is running" }));
});

export { helthCheck };
