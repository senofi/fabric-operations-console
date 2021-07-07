/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
import PropTypes from 'prop-types';
import React from 'react';
import SvgContainer from './SvgContainer';

const CircleFilled = ({ extendClass, height, title, width }) => {
	return (
		<SvgContainer width={width || '18px'}
			height={height || '18px'}
			extendClass={extendClass}
			viewBox="0 0 18 18"
		>
			<title>{title}</title>
			<g stroke="none"
				strokeWidth="1"
				fill="white"
			>
				<circle fill="white"
					cx="8"
					cy="8"
					r="8"
				/>
			</g>
		</SvgContainer>
	);
};

CircleFilled.propTypes = {
	extendClass: PropTypes.string,
	height: PropTypes.string,
	title: PropTypes.string,
	width: PropTypes.string,
};

export default CircleFilled;
